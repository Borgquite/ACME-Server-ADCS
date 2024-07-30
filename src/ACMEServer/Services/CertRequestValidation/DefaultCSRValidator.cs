using Microsoft.Extensions.Logging;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Th11s.ACMEServer.Model;
using Th11s.ACMEServer.Model.Services;

namespace Th11s.ACMEServer.Services.CertRequestValidation
{
    internal class DefaultCSRValidator : ICSRValidator
    {
        private readonly ILogger<DefaultCSRValidator> _logger;

        public DefaultCSRValidator(
            ILogger<DefaultCSRValidator> logger)
        {
            _logger = logger;
        }


        public Task<AcmeValidationResult> ValidateCsrAsync(Order order, string csr, CancellationToken cancellationToken)
        {
            _logger.LogDebug($"Attempting validation of CSR {csr}");
            try
            {
                // Load the CSR from the PEM string - this will throw if the CSR is invalid.
                // The hash algorithm name is not used here, but it is required by the API.
                var request = CertificateRequest.LoadSigningRequestPem(csr, HashAlgorithmName.SHA256);

                var validationContext = CSRValidationContext.FromRequestAndOrder(request, order);

                var subjectValidator = new SubjectValidator();
                if (!subjectValidator.IsValid(validationContext))
                {
                    _logger.LogDebug("CSR Validation failed due to invalid CN.");
                    return Task.FromResult(AcmeValidationResult.Failed(new AcmeError("badCSR", "CN Invalid.")));
                }

                var sanValidator = new AlternateNameValidator();
                if (!sanValidator.IsValid(validationContext))
                {
                    _logger.LogDebug("CSR Validation failed due to invalid SAN.");
                    return Task.FromResult(AcmeValidationResult.Failed(new AcmeError("badCSR", "SAN Invalid.")));
                }

                if (!validationContext.AreAllIdentifiersValid())
                {
                    _logger.LogDebug("CSR validation failed. Not all identifiers where present in either CN or SAN");
                    return Task.FromResult(AcmeValidationResult.Failed(new AcmeError("badCSR", "Missing identifiers in CN or SAN.")));
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, $"Validation of CSR failed with exception.");
                return Task.FromResult(AcmeValidationResult.Failed(new AcmeError("badCSR", "CSR could not be read.")));
            }

            _logger.LogDebug("CSR Validation succeeded.");
            return Task.FromResult(AcmeValidationResult.Success());
        }
    }
}
