#[cfg(test)]
mod tests {
    use crate::{
        obj::VerifyUser,
        operation::{generate_secret, get_secret},
    };

    const KEY_SIZE: usize = 10;
    const TOTP_SIZE: u32 = 6;

    #[test]
    fn totp_key_attribute() {
        let rand_secret = generate_secret(KEY_SIZE);
        assert_eq!(rand_secret.chars().count(), KEY_SIZE);
        for ch in rand_secret.chars() {
            assert!(ch.is_alphanumeric());
        }
    }

    #[test]
    fn test_emails() {
        let verify_user: Vec<(VerifyUser, bool)> = vec![
            (
                VerifyUser {
                    email: "abc@email.com".to_string(),
                    token: "400600".to_string(),
                },
                true,
            ),
            (
                VerifyUser {
                    email: "12abc@email.com".to_string(),
                    token: "400600".to_string(),
                },
                true,
            ),
            (
                VerifyUser {
                    email: "YYu1239oz.xyzf@email.com".to_string(),
                    token: "400600".to_string(),
                },
                true,
            ),
            (
                VerifyUser {
                    email: "abc@email.com".to_string(),
                    token: "40060".to_string(),
                },
                false,
            ),
            (
                VerifyUser {
                    email: "abc@emailcom".to_string(),
                    token: "400600".to_string(),
                },
                false,
            ),
            (
                VerifyUser {
                    email: "abcemail.com".to_string(),
                    token: "400600".to_string(),
                },
                false,
            ),
            (
                VerifyUser {
                    email: "abcemailcom".to_string(),
                    token: "400600".to_string(),
                },
                false,
            ),
        ];

        for v in verify_user.iter() {
            assert_eq!(v.0.is_valid(TOTP_SIZE), v.1);
        }
    }

    #[test]
    fn validate_totp() {
        let totp_vec = vec![
            ("aaabbbccc1".to_string(), true),
            ("aaabbbccc".to_string(), false),
            ("aaa$bbccc".to_string(), false),
            ("aaa12bccc1".to_string(), true),
            ("aaa12#ccc".to_string(), false),
            ("aaabbbcccd".to_string(), true),
            ("aaabbbccc*1".to_string(), false),
            ("1234567890".to_string(), true),
            ("123456789".to_string(), false),
            ("".to_string(), false),
        ];

        for i in totp_vec.iter() {
            let totp_sec = get_secret(&i.0, KEY_SIZE, TOTP_SIZE);
            assert_eq!(totp_sec.is_ok(), i.1);
        }
    }
}
