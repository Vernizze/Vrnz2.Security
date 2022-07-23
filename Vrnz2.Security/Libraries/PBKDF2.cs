using System;
using System.Security.Cryptography;
using System.Text;

namespace Vrnz2.Security.Libraries
{
    public class PBKDF2
    {
        #region Constants

        private const int HASH_ITERATIONS = 10000;
        private const int SALT_SIZE = 16;

        #endregion

        #region Methods

        /// <summary>
        /// Compare password hashes for equality. Uses a constant time comparison method.
        /// </summary>
        /// <param name="passwordHash1"></param>
        /// <param name="passwordHash2"></param>
        /// <returns></returns>
        public static bool Compare(string passwordHash1, string passwordHash2)
        {
            if (passwordHash1 == null || passwordHash2 == null)
                return false;

            int min_length = Math.Min(passwordHash1.Length, passwordHash2.Length);
            int result = 0;

            for (int i = 0; i < min_length; i++)
                result |= passwordHash1[i] ^ passwordHash2[i];

            return 0 == result;
        }

        /// <summary>
        /// Compute the hash using default generated salt. Will Generate a salt if non was assigned
        /// </summary>
        /// <param name="textToHash"></param>
        /// <returns></returns>
        public static string Compute(string textToHash)
        {
            if (string.IsNullOrEmpty(textToHash)) throw new InvalidOperationException("PlainText cannot be empty");

            return Compute(textToHash, GenerateSalt());
        }

        public static string Compute(string textToHash, string salt)
        {
            if (string.IsNullOrEmpty(textToHash)) throw new InvalidOperationException("PlainText cannot be empty");

            return CalculateHash(textToHash, salt);
        }

        /// <summary>
        /// Generates a salt with default salt size and iterations
        /// </summary>
        /// <returns>
        /// the generated salt
        /// </returns>
        /// <exception cref="System.InvalidOperationException"></exception>
        public static string GenerateSalt()
        {
            var result = string.Empty;

            if (SALT_SIZE < 1) throw new InvalidOperationException(string.Format("Cannot generate a salt of size {0}, use a value greater than 1, recommended: 16", SALT_SIZE));

            var rand = RandomNumberGenerator.Create();

            var ret = new byte[SALT_SIZE];

            rand.GetBytes(ret);

            //assign the generated salt in the format of {iterations}.{salt}
            result = string.Format("{0}.{1}", HASH_ITERATIONS, Convert.ToBase64String(ret));

            //result = Guid.NewGuid().ToString();

            return result;
        }

        private static string CalculateHash(string plainText, string salt)
        {
            //convert the salt into a byte array
            byte[] saltBytes = Encoding.UTF8.GetBytes(salt);
            var pbkdf2 = new Rfc2898DeriveBytes(plainText, saltBytes, HASH_ITERATIONS);
            var key = pbkdf2.GetBytes(SALT_SIZE);

            return Convert.ToBase64String(key);
        }

        #endregion
    }
}
