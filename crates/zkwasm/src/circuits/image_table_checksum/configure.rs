use std::marker::PhantomData;

use halo2_proofs::arithmetic::FieldExt;
use halo2_proofs::plonk::ConstraintSystem;
use halo2_proofs::plonk::Expression;
use halo2_proofs::plonk::VirtualCells;
use specs::encode::image_table::ImageTableEncoder;

use crate::curr;

use super::ImageTableConfig;

impl<F: FieldExt> ImageTableConfig<F> {
    pub(in crate::circuits) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let col = meta.advice_column();
        meta.enable_equality(col);
        Self {
            col,
            _mark: PhantomData,
        }
    }

    pub fn instruction_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        key: &'static str,
        expr: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(key, |meta| {
            vec![(
                ImageTableEncoder::Instruction.encode(expr(meta)),
                curr!(meta, self.col),
            )]
        });
    }

    pub fn init_memory_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        key: &'static str,
        expr: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(key, |meta| {
            vec![(
                ImageTableEncoder::InitMemory.encode(expr(meta)),
                curr!(meta, self.col),
            )]
        });
    }

    pub fn br_table_lookup(
        &self,
        meta: &mut ConstraintSystem<F>,
        key: &'static str,
        expr: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
    ) {
        meta.lookup_any(key, |meta| {
            vec![(
                ImageTableEncoder::BrTable.encode(expr(meta)),
                curr!(meta, self.col),
            )]
        });
    }
}