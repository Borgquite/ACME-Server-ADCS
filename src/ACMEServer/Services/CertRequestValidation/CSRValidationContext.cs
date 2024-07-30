using System.Security.Cryptography.X509Certificates;
using Th11s.ACMEServer.Model;

namespace Th11s.ACMEServer.Services.CertRequestValidation
{
    internal class CSRValidationContext
    {
        public CSRValidationContext(CertificateRequest request, IEnumerable<Identifier> identifiers)
        {
            Request = request;
            IdentifierValidationState = identifiers.ToDictionary(x => x, x => false);
        }


        public CertificateRequest Request { get; }

        public string? SubjectName { get; init; }
        public IReadOnlyList<string>? CommonNames { get; init; }

        public IReadOnlyList<X509SubjectAlternativeNameExtension>? AlternativeNameExtensions { get; init; }
        public IReadOnlyList<string>? SubjectAlternativeDNSNames { get; init; }

        public ICollection<Identifier> Identifiers => IdentifierValidationState.Keys;
        private IDictionary<Identifier, bool> IdentifierValidationState { get; }


        internal static CSRValidationContext FromRequestAndOrder(CertificateRequest request, Order order)
        {
            var (subjectName, commonNames) = TryParseSubject(request);
            var alternativeNames = CollectAlternateNames(request);

            var ctx = new CSRValidationContext(request, order.Identifiers)
            {
                SubjectName = subjectName,
                CommonNames = commonNames,

                AlternativeNameExtensions = alternativeNames
            };

            return ctx;
        }


        public void SetIdentifierToValid(Identifier identifier)
            => IdentifierValidationState[identifier] = true;

        public bool AreAllIdentifiersValid()
            => IdentifierValidationState.All(x => x.Value);

        private static (string? subjectName, List<string>? commonNames) TryParseSubject(CertificateRequest request)
        {
            try
            {
                var subjectName = request.SubjectName;

                if (subjectName == null)
                    return (null, null);

                var commonNames = subjectName.Name.Split(',', StringSplitOptions.TrimEntries)
                    .Select(x => x.Split('=', 2, StringSplitOptions.TrimEntries))
                    .Where(x => string.Equals("cn", x.First(), StringComparison.OrdinalIgnoreCase)) // Check for cn=
                    .Select(x => x.Last()) // take =value
                    .ToList();

                return (subjectName.Name, commonNames);
            }
            catch
            {
                return (null, null);
            }
        }

        private static (TODO TODO, TODO TODO) CollectAlternateNames(CertificateRequest request)
        {
            var subjectAlternateNames = new List<string>();

            var alternateNameExtensions = request.CertificateExtensions
                .OfType<X509SubjectAlternativeNameExtension>()
                .ToList();

            var subjectAlternateNames = alternateNameExtensions
                .SelectMany(x => x.EnumerateDnsNames())
                .ToList();

            foreach (var x509Ext in alternateNameExtensions)
            {
                var x509extData = x509Ext.RawData[EncodingType.XCN_CRYPT_STRING_BASE64];
                var alternativeNames = new CX509ExtensionAlternativeNames();
                alternativeNames.InitializeDecode(EncodingType.XCN_CRYPT_STRING_BASE64, x509extData);

                subjectAlternateNames.AddRange(alternativeNames.AlternativeNames.Cast<CAlternativeName>());
            }

            return subjectAlternateNames;
        }
    }
}
