export function getErrorMessage(error, fallback = "Beklenmeyen bir hata oluştu") {
  return error?.response?.data?.detail || error?.message || fallback;
}
