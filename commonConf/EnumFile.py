class DocumentType:
    Identity = 1
    Education = 2
    Insurance = 3
    OtherDocuments = 4
    RightOfWork = 5
    License = 6
    Cv = 7

class Days:
    Monday = 0
    Tuesday = 1
    Wednesday = 2
    Thursday = 3
    Friday = 4
    Saturday = 5
    Sunday = 6

class SortType:
  default = 0
  first_name =  1
  company_name = 2
  email = 3
  createdAt = 4
  fromm = 5
  to = 6
  branch_name = 7
  cs_in_use = 8
  pharmacy_service = 9


class Filters:
   default = 0
   deleted = 1
   blocked = 2
   country = 3
   city = 4

class EMAIL_TEMPLATES:
  LOCUM_SIGNUP= 1
  PHARMACY_SIGNUP= 2
  LOCUM_WELCOME= 3
  PHARMACY_WELCOME= 4
  LOCUM_OTP= 5
  PHARMACY_OTP= 6
  PHARMACY_JOB_COMPLETE= 7
  LOCUM_JOB_COMPLETE= 8
  LOCUM_JOB_RATING= 9
  PHARMACY_JOB_RATING = 10
  PHARMACY_INVOICE_RECEIVED =11
  LOCUM_INVOICE_RECEIVED = 12
  FORGOT_PASSWORD = 13
  LOGOUT = 14
  CONTACT_US_ADMIN = 15
  CONTACT_US_REVERT = 16



class FrontendState:
   Create = 1
   Update = 2
   Delete = 3