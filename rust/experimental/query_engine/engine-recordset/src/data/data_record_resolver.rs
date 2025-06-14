use std::{any::Any, cell::RefCell};

use crate::{Error, ValuePath, execution_context::ExecutionContext, primitives::AnyValue};

use super::DataRecord;

pub(crate) trait DynamicDataRecordAnyValueResolver: Any {
    fn read_value(
        &self,
        expression_id: usize,
        execution_context: &dyn ExecutionContext,
        path: &ValuePath,
        data_record: &dyn DataRecord,
        action: &mut dyn DataRecordAnyValueReadCallback,
    ) -> Result<(), Error>;
}

type DataRecordAnyValueResolverReadValueCallback<T> =
    dyn for<'a, 'b> Fn(&'a ValuePath, &'b T) -> DataRecordReadAnyValueResult<'b>;
type DataRecordAnyValueResolverSetValueCallback<T> =
    dyn Fn(&ValuePath, &mut T, AnyValue) -> DataRecordSetAnyValueResult;
type DataRecordAnyValueResolverRemoveValueCallback<T> =
    dyn Fn(&ValuePath, &mut T) -> DataRecordRemoveAnyValueResult;

pub struct DataRecordAnyValueResolver<T: DataRecord> {
    path: ValuePath,
    read_value_fn: Box<DataRecordAnyValueResolverReadValueCallback<T>>,
    set_value_fn: Box<DataRecordAnyValueResolverSetValueCallback<T>>,
    remove_value_fn: Box<DataRecordAnyValueResolverRemoveValueCallback<T>>,
}

impl<T: DataRecord> DataRecordAnyValueResolver<T> {
    pub fn new(
        path: ValuePath,
        read_value: impl for<'a, 'b> Fn(&'a ValuePath, &'b T) -> DataRecordReadAnyValueResult<'b>
        + 'static,
        set_value: impl Fn(&ValuePath, &mut T, AnyValue) -> DataRecordSetAnyValueResult + 'static,
        remove_value: impl Fn(&ValuePath, &mut T) -> DataRecordRemoveAnyValueResult + 'static,
    ) -> DataRecordAnyValueResolver<T> {
        Self {
            path,
            read_value_fn: Box::new(read_value),
            set_value_fn: Box::new(set_value),
            remove_value_fn: Box::new(remove_value),
        }
    }

    pub fn new_no_op() -> DataRecordAnyValueResolver<T> {
        DataRecordAnyValueResolver::new(
            ValuePath::new("").unwrap(),
            |_, _| DataRecordReadAnyValueResult::NotFound,
            |_, _, _| DataRecordSetAnyValueResult::NotFound,
            |_, _| DataRecordRemoveAnyValueResult::NotFound,
        )
    }

    pub(crate) fn read_value<F>(&self, data_record: &RefCell<T>, action: F)
    where
        F: FnOnce(DataRecordReadAnyValueResult),
    {
        let borrow = data_record.borrow();

        let result = (self.read_value_fn)(&self.path, &borrow);

        action(result);
    }

    pub(crate) fn read_value_direct<F>(&self, data_record: &T, action: F)
    where
        F: FnOnce(DataRecordReadAnyValueResult),
    {
        let result = (self.read_value_fn)(&self.path, data_record);

        action(result);
    }

    pub(crate) fn set_value(
        &self,
        data_record: &RefCell<T>,
        value: AnyValue,
    ) -> DataRecordSetAnyValueResult {
        let mut borrow = data_record.borrow_mut();

        (self.set_value_fn)(&self.path, &mut borrow, value)
    }

    pub(crate) fn remove_value(&self, data_record: &RefCell<T>) -> DataRecordRemoveAnyValueResult {
        let mut borrow = data_record.borrow_mut();

        (self.remove_value_fn)(&self.path, &mut borrow)
    }
}

#[derive(Debug)]
pub enum DataRecordReadAnyValueResult<'a> {
    NotFound,
    Found(&'a AnyValue),
}

#[derive(Debug)]
pub enum DataRecordReadMutAnyValueResult<'a> {
    NotFound,
    NotSupported(&'static str),
    Found(&'a mut AnyValue),
}

#[derive(Debug)]
pub enum DataRecordSetAnyValueResult {
    NotFound,
    NotSupported(&'static str),
    Created,
    Updated(AnyValue),
}

#[derive(Debug)]
pub enum DataRecordRemoveAnyValueResult {
    NotFound,
    NotSupported(&'static str),
    Removed(AnyValue),
}

pub(crate) trait DataRecordAnyValueReadCallback {
    fn invoke_once(&mut self, result: DataRecordReadAnyValueResult);
}

pub(crate) struct DataRecordAnyValueReadClosureCallback<F>
where
    F: FnOnce(DataRecordReadAnyValueResult),
{
    callback: Option<F>,
}

impl<F> DataRecordAnyValueReadClosureCallback<F>
where
    F: FnOnce(DataRecordReadAnyValueResult),
{
    pub fn new(callback: F) -> DataRecordAnyValueReadClosureCallback<F> {
        Self {
            callback: Some(callback),
        }
    }
}

impl<F> DataRecordAnyValueReadCallback for DataRecordAnyValueReadClosureCallback<F>
where
    F: FnOnce(DataRecordReadAnyValueResult),
{
    fn invoke_once(&mut self, result: DataRecordReadAnyValueResult) {
        let callback = self.callback.take();
        if let Some(c) = callback {
            (c)(result);
        }
    }
}
