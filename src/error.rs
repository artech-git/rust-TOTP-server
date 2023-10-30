
use thiserror::Error;

pub type BackendResult<T,E> = Result<T, BackendError<E>>; 

#[derive(Debug)]
pub struct BackendError<T> {
    error: T
} 

// impl<T> std::convert::From<T> for BackendError<T>
// where T: Into<ErrorTypes> {

// }

#[derive(Error, Debug)]
enum ErrorTypes { 
    
    #[error("data store disconnected")]
    Disconnect(#[from] std::io::Error),


}