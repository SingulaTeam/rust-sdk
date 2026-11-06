//! Computing the circuit's witness from its inputs.
//!
//! The Semaphore circuit is compiled ahead of time, by circom-witnesscalc,
//! into a graph: a flat list of nodes, each an input, a constant or one
//! arithmetic operation on earlier nodes. Evaluating the nodes in order gives
//! every signal; the witness is the subset the proving key expects.
//!
//! Only the operations the Semaphore graph uses are implemented, and a graph
//! that uses anything else is refused when it is loaded, not when it is
//! evaluated. Every node index is checked at load too, so evaluation itself
//! cannot fail.
//!
//! # File format
//!
//! ```text
//! "wtns.graph.001"            magic
//! u64 little-endian           node count N
//! N × varint-length ‖ Node    protobuf, see circom-witnesscalc's messages.proto
//! varint-length ‖ Metadata    protobuf: witness signals, input offsets, prime
//! ```

use std::collections::HashMap;

use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger as _, Field as _, PrimeField as _, Zero as _};

const MAGIC: &[u8] = b"wtns.graph.001";

/// Why a witness graph could not be loaded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GraphError {
    /// The bytes are not a witness graph, or are cut short.
    #[error("the witness graph is malformed: {0}")]
    Malformed(&'static str),
    /// The graph uses an operation this evaluator does not implement.
    #[error("the witness graph uses an operation this crate does not implement ({0})")]
    Unsupported(&'static str),
    /// The graph is for another field than BN254's scalar field.
    #[error("the witness graph is for another field")]
    WrongField,
    /// The graph lacks an input the circuit is given.
    #[error("the witness graph has no input `{0}`")]
    MissingInput(&'static str),
}

#[derive(Debug, Clone, Copy)]
enum Node {
    Input(usize),
    Constant(Fr),
    Neg(usize),
    Op(Op, usize, usize),
    /// `if a != 0 { b } else { c }`.
    Ternary(usize, usize, usize),
}

#[derive(Debug, Clone, Copy)]
enum Op {
    Mul,
    Div,
    Add,
    Sub,
    Neq,
    /// Shift right by a constant number of bits, below the field's width;
    /// checked at load.
    Shr(u32),
    BitAnd,
}

/// Where each named input starts in the input vector, and how many elements
/// it has.
type InputLayout = HashMap<String, (usize, usize)>;

/// A loaded witness graph.
pub(crate) struct Graph {
    nodes: Vec<Node>,
    /// Which node holds each witness signal, in witness order.
    witness: Vec<usize>,
    inputs: InputLayout,
    /// Length of the input vector; element 0 is the constant one.
    input_len: usize,
}

impl Graph {
    /// Parses and checks a graph.
    pub(crate) fn parse(bytes: &[u8]) -> Result<Self, GraphError> {
        let mut r = Reader(bytes);
        if r.take(MAGIC.len())? != MAGIC {
            return Err(GraphError::Malformed("bad magic"));
        }
        let count = usize::try_from(u64::from_le_bytes(r.array()?))
            .map_err(|_| GraphError::Malformed("node count"))?;

        let mut nodes = Vec::with_capacity(count.min(bytes.len()));
        for i in 0..count {
            let node = parse_node(r.message()?, &nodes)?;
            // Operands must already exist, which also rules out cycles.
            if node.operands().any(|o| o >= i) {
                return Err(GraphError::Malformed("operand refers forward"));
            }
            nodes.push(node);
        }
        let (witness, inputs) = parse_metadata(r.message()?)?;
        if witness.iter().any(|&w| w >= nodes.len()) {
            return Err(GraphError::Malformed("witness signal out of range"));
        }
        let input_len = inputs
            .values()
            .map(|&(at, len)| at + len)
            .max()
            .unwrap_or(0)
            + 1;
        if nodes
            .iter()
            .any(|n| matches!(n, Node::Input(i) if *i >= input_len))
        {
            return Err(GraphError::Malformed("input index out of range"));
        }
        Ok(Self {
            nodes,
            witness,
            inputs,
            input_len,
        })
    }

    /// The witness for these named inputs.
    pub(crate) fn witness(&self, inputs: &[(&'static str, &[Fr])]) -> Result<Vec<Fr>, GraphError> {
        let mut vector = vec![Fr::zero(); self.input_len];
        vector[0] = Fr::ONE;
        for &(name, values) in inputs {
            let &(at, len) = self
                .inputs
                .get(name)
                .ok_or(GraphError::MissingInput(name))?;
            if values.len() != len {
                return Err(GraphError::MissingInput(name));
            }
            vector[at..at + len].copy_from_slice(values);
        }

        let mut values: Vec<Fr> = Vec::with_capacity(self.nodes.len());
        for node in &self.nodes {
            let v = |i: usize| values[i];
            let value = match *node {
                Node::Input(i) => vector[i],
                Node::Constant(c) => c,
                Node::Neg(a) => -v(a),
                Node::Ternary(a, b, c) => {
                    if v(a).is_zero() {
                        v(c)
                    } else {
                        v(b)
                    }
                }
                Node::Op(op, a, b) => op.apply(v(a), v(b)),
            };
            values.push(value);
        }
        Ok(self.witness.iter().map(|&i| values[i]).collect())
    }
}

impl Node {
    fn operands(self) -> impl Iterator<Item = usize> {
        let (a, b, c) = match self {
            Self::Input(_) | Self::Constant(_) => (None, None, None),
            Self::Neg(a) => (Some(a), None, None),
            Self::Op(_, a, b) => (Some(a), Some(b), None),
            Self::Ternary(a, b, c) => (Some(a), Some(b), Some(c)),
        };
        a.into_iter().chain(b).chain(c)
    }
}

impl Op {
    /// circom's semantics for each operation over the field.
    fn apply(self, a: Fr, b: Fr) -> Fr {
        match self {
            Self::Mul => a * b,
            // circom defines x / 0 as 0 rather than failing.
            Self::Div => b.inverse().map_or(Fr::zero(), |inv| a * inv),
            Self::Add => a + b,
            Self::Sub => a - b,
            Self::Neq => Fr::from(a != b),
            Self::Shr(bits) => {
                // Shifting right only shrinks a value that was below the modulus.
                Fr::from_bigint(a.into_bigint() >> bits).unwrap_or_default()
            }
            Self::BitAnd => {
                let (x, y) = (a.into_bigint(), b.into_bigint());
                let mut limbs = [0u64; 4];
                for (l, (p, q)) in limbs.iter_mut().zip(x.0.iter().zip(y.0.iter())) {
                    *l = p & q;
                }
                // Both operands are below the modulus, so their AND is too.
                Fr::from_bigint(BigInt(limbs)).unwrap_or_default()
            }
        }
    }
}

/// One node, given the nodes before it (a shift needs its constant operand).
fn parse_node(message: &[u8], earlier: &[Node]) -> Result<Node, GraphError> {
    let (field, body) = Reader(message).only_submessage()?;
    let f = Fields::parse(body)?;
    match field {
        1 => Ok(Node::Input(f.index(1)?)),
        2 => {
            let value = Fields::parse(f.bytes(1))?;
            let le = value.bytes(1);
            if le.len() > 32 {
                return Err(GraphError::Malformed("constant too wide"));
            }
            Ok(Node::Constant(Fr::from_le_bytes_mod_order(le)))
        }
        3 => match f.varint(1) {
            0 => Ok(Node::Neg(f.index(2)?)),
            _ => Err(GraphError::Unsupported(
                "unary operation other than negation",
            )),
        },
        4 => {
            let (a, b) = (f.index(2)?, f.index(3)?);
            let op = match f.varint(1) {
                0 => Op::Mul,
                1 => Op::Div,
                2 => Op::Add,
                3 => Op::Sub,
                8 => Op::Neq,
                16 => Op::Shr(constant_shift(earlier, b)?),
                18 => Op::BitAnd,
                _ => return Err(GraphError::Unsupported("binary operation")),
            };
            Ok(Node::Op(op, a, b))
        }
        5 => match f.varint(1) {
            0 => Ok(Node::Ternary(f.index(2)?, f.index(3)?, f.index(4)?)),
            _ => Err(GraphError::Unsupported("ternary operation")),
        },
        _ => Err(GraphError::Malformed("unknown node kind")),
    }
}

/// The shift amount of a right shift, which must be a constant below the
/// field's 254 bits: a shift by a computed or "negative" amount is a left
/// shift in circom, which the Semaphore graph never does.
fn constant_shift(earlier: &[Node], operand: usize) -> Result<u32, GraphError> {
    match earlier.get(operand) {
        Some(Node::Constant(c)) => {
            let n = c.into_bigint();
            if n.0[1..].iter().any(|&l| l != 0) || n.0[0] >= u64::from(Fr::MODULUS_BIT_SIZE) {
                return Err(GraphError::Unsupported(
                    "shift by more than the field's width",
                ));
            }
            u32::try_from(n.0[0]).map_err(|_| GraphError::Unsupported("shift amount"))
        }
        _ => Err(GraphError::Unsupported("shift by a computed amount")),
    }
}

fn parse_metadata(message: &[u8]) -> Result<(Vec<usize>, InputLayout), GraphError> {
    let mut witness = Vec::new();
    let mut inputs = HashMap::new();
    let mut prime = None;
    let mut r = Reader(message);
    while !r.0.is_empty() {
        match r.key()? {
            // witnessSignals, packed or not.
            (1, Wire::Len) => {
                let mut packed = Reader(r.len_delimited()?);
                while !packed.0.is_empty() {
                    witness.push(to_index(packed.varint()?)?);
                }
            }
            (1, Wire::Varint) => witness.push(to_index(r.varint()?)?),
            // inputs: map<string, SignalDescription>.
            (2, Wire::Len) => {
                let entry = Fields::parse(r.len_delimited()?)?;
                let name = std::str::from_utf8(entry.bytes(1))
                    .map_err(|_| GraphError::Malformed("input name"))?;
                let signal = Fields::parse(entry.bytes(2))?;
                inputs.insert(name.to_owned(), (signal.index(1)?, signal.index(2)?));
            }
            (3, Wire::Len) => prime = Some(Fields::parse(r.len_delimited()?)?.bytes(1).to_vec()),
            (_, wire) => r.skip(wire)?,
        }
    }
    let modulus = Fr::MODULUS.to_bytes_le();
    if prime.is_some_and(|p| p != modulus) {
        return Err(GraphError::WrongField);
    }
    Ok((witness, inputs))
}

fn to_index(v: u64) -> Result<usize, GraphError> {
    usize::try_from(v).map_err(|_| GraphError::Malformed("index too large"))
}

/// Protobuf wire types this format uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    Varint,
    Fixed64,
    Len,
    Fixed32,
}

/// A cursor over protobuf-encoded bytes.
struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], GraphError> {
        if self.0.len() < n {
            return Err(GraphError::Malformed("truncated"));
        }
        let (head, rest) = self.0.split_at(n);
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], GraphError> {
        let mut out = [0; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn varint(&mut self) -> Result<u64, GraphError> {
        let mut value = 0u64;
        for shift in (0..64).step_by(7) {
            let [b] = self.array()?;
            value |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(GraphError::Malformed("varint too long"))
    }

    fn len_delimited(&mut self) -> Result<&'a [u8], GraphError> {
        let len = to_index(self.varint()?)?;
        self.take(len)
    }

    /// A length-delimited message at the top level of the file.
    fn message(&mut self) -> Result<&'a [u8], GraphError> {
        self.len_delimited()
    }

    fn key(&mut self) -> Result<(u64, Wire), GraphError> {
        let key = self.varint()?;
        let wire = match key & 7 {
            0 => Wire::Varint,
            1 => Wire::Fixed64,
            2 => Wire::Len,
            5 => Wire::Fixed32,
            _ => return Err(GraphError::Malformed("wire type")),
        };
        Ok((key >> 3, wire))
    }

    fn skip(&mut self, wire: Wire) -> Result<(), GraphError> {
        match wire {
            Wire::Varint => self.varint().map(drop),
            Wire::Fixed64 => self.take(8).map(drop),
            Wire::Len => self.len_delimited().map(drop),
            Wire::Fixed32 => self.take(4).map(drop),
        }
    }

    /// The single length-delimited field of a `oneof` wrapper.
    fn only_submessage(mut self) -> Result<(u64, &'a [u8]), GraphError> {
        match self.key()? {
            (field, Wire::Len) => {
                let body = self.len_delimited()?;
                if self.0.is_empty() {
                    Ok((field, body))
                } else {
                    Err(GraphError::Malformed("node has more than one kind"))
                }
            }
            _ => Err(GraphError::Malformed("node kind")),
        }
    }
}

/// The scalar and byte fields of a small message, by field number; absent
/// fields read as zero or empty, as proto3 defines them.
struct Fields<'a> {
    varints: [u64; 5],
    bytes: [&'a [u8]; 3],
}

impl<'a> Fields<'a> {
    fn parse(message: &'a [u8]) -> Result<Self, GraphError> {
        let mut f = Self {
            varints: [0; 5],
            bytes: [&[]; 3],
        };
        let mut r = Reader(message);
        while !r.0.is_empty() {
            match r.key()? {
                (n @ 1..=4, Wire::Varint) => f.varints[to_index(n)?] = r.varint()?,
                (n @ 1..=2, Wire::Len) => f.bytes[to_index(n)?] = r.len_delimited()?,
                (_, wire) => r.skip(wire)?,
            }
        }
        Ok(f)
    }

    fn varint(&self, field: usize) -> u64 {
        self.varints[field]
    }

    fn index(&self, field: usize) -> Result<usize, GraphError> {
        to_index(self.varints[field])
    }

    fn bytes(&self, field: usize) -> &'a [u8] {
        self.bytes[field]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_the_bundled_graph() {
        let graph = Graph::parse(super::super::prover::GRAPH).expect("the bundled graph loads");
        for name in [
            "secret",
            "merkleProofLength",
            "merkleProofIndex",
            "merkleProofSiblings",
            "message",
            "scope",
        ] {
            assert!(graph.inputs.contains_key(name), "{name}");
        }
        assert_eq!(graph.inputs["merkleProofSiblings"].1, 16);
    }

    #[test]
    fn refuses_what_is_not_a_graph() {
        assert_eq!(
            Graph::parse(b"not a witness graph at all").err(),
            Some(GraphError::Malformed("bad magic"))
        );
        let mut cut = super::super::prover::GRAPH.to_vec();
        cut.truncate(1000);
        assert_eq!(
            Graph::parse(&cut).err(),
            Some(GraphError::Malformed("truncated"))
        );
    }

    #[test]
    fn follows_circom_semantics() {
        let three = Fr::from(3u8);
        assert_eq!(Op::Div.apply(three, Fr::zero()), Fr::zero());
        assert_eq!(Op::Div.apply(three, three), Fr::ONE);
        assert_eq!(Op::Shr(1).apply(Fr::from(7u8), Fr::zero()), three);
        assert_eq!(
            Op::BitAnd.apply(Fr::from(6u8), Fr::from(3u8)),
            Fr::from(2u8)
        );
        assert_eq!(Op::Neq.apply(three, three), Fr::zero());
    }
}
