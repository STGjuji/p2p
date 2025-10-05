public class SecurityProvider
{
    private readonly RSACryptoServiceProvider _rsaProvider;
    private readonly Aes _aesProvider;

    public SecurityProvider()
    {
        // Using RSA-4096 for maximum security
        _rsaProvider = new RSACryptoServiceProvider(4096);
        _aesProvider = Aes.Create();
        _aesProvider.KeySize = 256; // AES-256 encryption
        _aesProvider.Mode = CipherMode.CBC;
        _aesProvider.Padding = PaddingMode.PKCS7;
    }

    public byte[] EncryptFile(byte[] fileData, byte[] key, byte[] iv)
    {
        using var encryptor = _aesProvider.CreateEncryptor(key, iv);
        using var msEncrypt = new MemoryStream();
        using var csEncrypt = new CryptoStream(
            msEncrypt,
            encryptor,
            CryptoStreamMode.Write);

        csEncrypt.Write(fileData, 0, fileData.Length);
        csEncrypt.FlushFinalBlock();

        return msEncrypt.ToArray();
    }
}

public class SecureWebSocketManager
{
    private readonly WebSocketServer _server;
    private readonly concurrentDictionary<string, WebSocket> _clients;
    private readonly X509Certificate2 _serverCertificate;
    private readonly SecurityProvider _securityProvider;

    public SecureWebSocketManager(
        strung listeningUrl,
        X509Certificate2 serverCertificate
    )
    {
        _server = new WebSocketServer(ListenUrl);
        _clients = new ConcurrentDictionary<string, IWebSocketConnection>();
        _serverCertificate = serverCertificate;
        _securityProvider = new SecurityProvider();

        configureSecurityOptions();
    }


}