// Response handler utility functions

const sendResponse = (res, success, statusCode, message, data = null) => {
  return res.status(statusCode).json({
    success: success,
    status: statusCode,
    message: message,
    data: data || undefined,
  });
};

// General error handling function
const handleError = (res, statusCode, message) => {
  return sendResponse(res, false, statusCode, message);
};

// Success handler function
const handleSuccess = (res, statusCode, message, ...data) => {
  return sendResponse(res, true, statusCode, message, data.length > 0 ? data[0] : null);
};

// Validation error handler
const vallidationErrorHandle = (res, error) => {
  const errorMessage = error.errors[0].msg;
  return sendResponse(res, false, 400, errorMessage);
};

// Export the functions for reuse
export { handleError, handleSuccess, vallidationErrorHandle };
