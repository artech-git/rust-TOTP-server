#[cfg(test)]
mod tests {
    use crate::{
        obj::{VerifyUser, KEY_MAP},
        operation::{generate_secret, get_secret},
    };

    #[test]
    fn totp_key_attribute() {
        let rand_secret = generate_secret();
        let key_size = KEY_MAP
            .get(&"KEY_SIZE".to_string())
            .expect("key not found")
            .parse::<usize>()
            .unwrap();
        assert_eq!(rand_secret.chars().count(), key_size);
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
            assert_eq!(v.0.is_valid(), v.1);
        }
    }

    // #[test]
    // #[should_panic(expected = "invalid secret based totp generation call")]
    // fn validate_totp() {
    //     let secret = generate_secret();
    //     let totp = get_secret(&secret).unwrap();
    //     let totp_vec = vec![
    //         ("aaabbbccc".to_string(), true),
    //         ("aaa$bbccc".to_string(), false),
    //         ("aaa12bccc".to_string(), true),
    //         ("aaa12#ccc".to_string(), false),
    //         ("aaabbbcccd".to_string(), false),
    //         ("aaabbbccc*1".to_string(), false),
    //         ("12345678".to_string(), true),
    //         ("123456789".to_string(), false),
    //         ("".to_string(), false),
    //     ];

    //     for I in totp_vec.iter() {
    //         let totp_sec = get_secret(&(I.0));
    //         if totp_sec.is_ok() {
    //             let _ = totp_sec.unwrap();
    //         }
    //     }
    // }
}
