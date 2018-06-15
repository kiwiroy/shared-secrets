library(PKI)
library(R6)
library(base64enc)

sharedSecret <-
  R6Class("SharedSecret",
          class = FALSE,
          cloneable = FALSE,
          private = list(
            ## decrypt symmetric key from disk
            decrypt_sym_key = function() {
              if(length(self$rsa_password) > 1) {
                return(self$rsa_password)
              }
              if(!file.exists(self$symmetric_file)) {
                return(NA)
              }
              contents <- readBin(con = self$symmetric_file, raw(), n = 256, size = 1)
              caught <- tryCatch(
                {
                  PKI::PKI.decrypt(contents, key = self$key)
                },
                error = function(cond) {
                  message("decrypting symmetric file failed")
                  message(cond)
                },
                finally = {}
              )
              if(class(caught) == "raw") {
                message("decrypting symmetric file success")
                self$rsa_password <- caught
              }
              return(caught)
            },
            ## enc dec
            encrypt_sym_key_decrypt = function() {
              file <- self$symmetric_file
              if(file.exists(file)) {
                return(private$decrypt_sym_key())
              }
              symmetric_password <-
                PKI::PKI.encrypt(charToRaw(base64encode(PKI::PKI.random(32))), key = self$key)
              writeBin(symmetric_password, con = file, raw())
              return(private$decrypt_sym_key())
            }
          ),
          public = list(
            symmetric_file = NA_character_,
            key_file       = NA_character_,
            key            = NULL,
            rsa_password   = charToRaw(""),
            ## initialisation
            initialize = function(symmetric_file = "symmetric.rsa",
                                  key_file = NA_character_) {
              self$rsa_password   <- charToRaw("")
              self$symmetric_file <- symmetric_file
              self$key_file       <- key_file
              if(is.na(key_file) == FALSE) {
                ## load key file if exists
                if (file.exists(key_file)) {
                  self$key <- PKI::PKI.load.key(file    = key_file,
                                                format  = "PEM",
                                                private = TRUE)
                } else {
                  ## create if not
                  create_keys(key_file)
                }
              }
            },

            ## create new key
            create_keys = function(key_file) {
              self$key_file <- key_file
              self$key      <- PKI::PKI.genRSAkey(2048)
              # write to disk
              dir.create(dirname(self$key_file), recursive = TRUE)
              PKI::PKI.save.key(key = self$key, format = "PEM", private = TRUE,
                                target = self$key_file)
              PKI::PKI.save.key(key = self$key, format = "PEM", private = FALSE,
                                target = paste(self$key_file, "pub", collapse = "."))
              key
            },

            ## decrypt data
            decrypt_data = function(data) {
              decrypted <- PKI::PKI.decrypt(data,
                                            key    = private$encrypt_sym_key_decrypt(),
                                            cipher = "aes256cbc")
              decrypted
            },

            ## encrypt data func
            encrypt_data = function(data) {
              encrypted <- NA
              if(class(data) == "character") {
                tryCatch({
                  encrypted <- PKI::PKI.encrypt(charToRaw(data),
                                                key    = private$encrypt_sym_key_decrypt(),
                                                cipher = "aes256cbc")
                },
                error = function(cond) {
                  message("encryption failed")
                  message(cond)
                })
              } else {
                tryCatch({
                  encrypted <- PKI::PKI.encrypt(data,
                                                key    = private$encrypt_sym_key_decrypt(),
                                                cipher = "aes256cbc")
                },
                error = function(cond) {
                  message("encryption failed")
                })
              }
              encrypted
            },
            encrypt_file = function(file, n = 1e3) {
              self$encrypt_data(paste(readLines(con = file, n = n), collapse = "\n"))
            }
          ))
