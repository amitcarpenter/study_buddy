
export const handleError = (res, statusCode, message) => {
  return res.status(200).send({
    success: false,
    status: statusCode,
    message: message
  });
};

export const handleSuccess = (res, statusCode, message, ...data) => {
  return res.status(200).json({
    success: true,
    status: statusCode,
    message: message,
    data: data.length > 0 ? data[0] : undefined,
  });
};

export const joiErrorHandle = (res, error) => {
  return res.status(200).send({
    success: false,
    status: 400,
    message: error.details[0].message
  });
};


