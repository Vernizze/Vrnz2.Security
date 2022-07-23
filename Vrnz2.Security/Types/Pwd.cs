using Vrnz2.Infra.CrossCutting.Extensions;
using Vrnz2.Security.Libraries;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security;
using System.Text.RegularExpressions;

namespace Vrnz2.Security.Types
{
    public struct Pwd
    {
        #region Constants

        private const string SPECIAL_CHARS = @"\|!#$%&/()=?»«@£§€{}.-;'<>_,";

        #endregion

        #region Variables

        private readonly SecureString _secureString;

        #endregion

        #region Atributes

        public readonly bool IsValid { get; }

        public string Value { get; private set; }

        #endregion

        #region Constructors

        public Pwd(string value)
            : this()
        {
            this.IsValid = Valid(value);

            if (this.IsValid)
            {
                using (var secureString = new SecureString())
                {
                    value.ToCharArray().ToList().ForEach(c => secureString.AppendChar(c));

                    _secureString = secureString.Copy();
                }
            }
        }

        #endregion

        #region Operators

        public static implicit operator Pwd(string value)
            => new Pwd(value);

        #endregion

        #region Methods

        public static bool Valid(string value)
            =>
                !string.IsNullOrEmpty(value) &&                                                 //Not Null or Empty
                (value.ToCharArray().Intersect(SPECIAL_CHARS.ToCharArray())).HaveAny() &&       //Must have Special Character
                new Regex(@"[0-9]+").IsMatch(value) &&                                          //Must have Number
                new Regex(@"[A-Z]+").IsMatch(value) &&                                          //Must have Upper Case Letter
                new Regex(@".{8,}").IsMatch(value) &&                                           //Must have eight characters 
                !(new Regex(@" ").IsMatch(value));                                              //Don't have white spaces

        public string GetHash(string salt)
        {
            if (_secureString.IsNotNull() && !string.IsNullOrEmpty(salt))
                Value = PBKDF2.Compute(Marshal.PtrToStringUni(Marshal.SecureStringToBSTR(_secureString)), salt);

            return Value;
        }

        #endregion       
    }
}
