from frappe.model.document import Document


class YOBAuthSettings(Document):
    def validate(self):
        self.otp_length = min(max(int(self.otp_length or 6), 4), 8)
        self.otp_expiry_seconds = min(max(int(self.otp_expiry_seconds or 300), 60), 900)
        self.otp_resend_seconds = min(max(int(self.otp_resend_seconds or 60), 15), 600)
        self.max_otp_attempts = min(max(int(self.max_otp_attempts or 5), 1), 10)
        self.max_otp_requests_per_hour = min(max(int(self.max_otp_requests_per_hour or 8), 1), 30)
