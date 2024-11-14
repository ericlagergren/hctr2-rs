// cipher::{
//     consts::U16, BlockCipher, BlockDecrypt, BlockEncrypt, Key, KeyInit,
//     KeySizeUser,
// },

// impl<C> KeySizeUser for Cipher<C>
// where
//     C: BlockCipher<BlockSize = U16> + KeyInit,
// {
//     type KeySize = C::KeySize;
// }

// impl<C> KeyInit for Cipher<C> where
//     C: BlockCipher<BlockSize = U16> + BlockEncrypt + KeyInit
// {
// }
