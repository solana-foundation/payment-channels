#[cfg(test)]
mod channel_layout {
    use crate::state::Channel;

    #[test]
    fn size_is_200_bytes() {
        assert_eq!(core::mem::size_of::<Channel>(), 200);
    }
}
