using System;
using System.IO;
using System.Security.Cryptography;
using BlubLib.Security.Cryptography;

namespace ProudNet
{
    internal class EncryptContext : IDisposable
    {
        public RijndaelManaged AES { get; private set; }
        public ushort EncryptCounter { get; private set; }
        public ushort DecryptCounter { get; private set; }

        public EncryptContext(int keySize)
        {
            AES = new RijndaelManaged
            {
                BlockSize = keySize,
                KeySize = keySize,
                Padding = PaddingMode.None,
                Mode = CipherMode.ECB,
            };
            AES.GenerateKey();
        }

        public EncryptContext(byte[] key)
        {
            AES = new RijndaelManaged
            {
                BlockSize = key.Length * 8,
                KeySize = key.Length * 8,
                Padding = PaddingMode.None,
                Mode = CipherMode.ECB,
                Key = key
            };
        }

        public byte[] Encrypt(byte[] data)
        {
            ++EncryptCounter;

            var checksum = Hash.GetUInt32<CRC32>(data);
            var blockSize = AES.BlockSize / 8;
            var padding = blockSize - (data.Length + 4 + 1) % blockSize;
            using (var writer = new BinaryWriter(new MemoryStream()))
            {
                writer.Write((byte)padding);
                writer.Write(checksum);
                writer.Write(data);
                writer.Fill(padding);

                writer.BaseStream.Position = 0;
                return AES.Encrypt(writer.BaseStream);
            }
        }

        public byte[] Decrypt(byte[] data)
        {
            ++DecryptCounter;
            var decrypted = AES.Decrypt(data);
            using (var reader = decrypted.ToBinaryReader())
            {
                var padding = reader.ReadByte();
                var checksum = reader.ReadUInt32();
                decrypted = reader.ReadBytes((int)(reader.BaseStream.Length - 5 - padding));

                if (checksum != Hash.GetUInt32<CRC32>(decrypted))
                    throw new ProudException("Received corrupted data");

                return decrypted;
            }
        }

        public void Dispose()
        {
            if (AES != null)
            {
                AES.Dispose();
                AES = null;
            }
        }
    }
}
