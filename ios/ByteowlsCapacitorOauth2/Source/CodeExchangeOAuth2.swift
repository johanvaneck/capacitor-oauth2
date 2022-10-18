import OAuthSwift

public class CodeExchangeOAuth2: OAuth2Swift {
    
    var codeExchangeUrl: String?
    
    public convenience init(consumerKey: String, authorizeUrl: String, codeExchangeUrl: String, responseType: String) {
        self.init(consumerKey: consumerKey, consumerSecret: "", authorizeUrl: authorizeUrl, responseType: responseType)
        self.codeExchangeUrl = codeExchangeUrl
    }
    
    open override func postOAuthAccessTokenWithRequestToken(
        byCode code: String,
        callbackURL: URL?,
        headers: OAuthSwift.Headers? = nil,
        completionHandler completion: @escaping TokenCompletionHandler
    ) -> OAuthSwiftRequestHandle? {
        
        var parameters = OAuthSwift.Parameters()
        parameters["code"] = code
        parameters["redirect_uri"] = callbackURL!.absoluteString.removingPercentEncoding
        
        let completionHandler: OAuthSwiftHTTPRequest.CompletionHandler = { (_ result: Result<OAuthSwiftResponse, OAuthSwiftError>) in
            switch result {
            case .success(let response):
                
                let responseJSON: Any? = try? response.jsonObject(options: .mutableContainers)
                
                let responseParameters: OAuthSwift.Parameters
                
                if let jsonDico = responseJSON as? [String:Any] {
                    responseParameters = jsonDico
                } else {
                    responseParameters = [:]
                }
                completion(.success( ( self.client.credential, response, responseParameters ) ) )
            case .failure(let error):
                completion(.failure(error))
                print("Error while parsing response.")
            }
        }
        
        guard let codeExchangeUrl = self.codeExchangeUrl else {
            let message = NSLocalizedString("code exchange for token url not defined", comment: "code exchange for token url not defined with code type auth")
            completion((.failure(OAuthSwiftError.configurationError(message: message)))!)
            return nil
        }

        // TODO abstract to make universal
        parameters["platform"] = "ios"
        let json = try! JSONSerialization.data(withJSONObject: parameters, options: JSONSerialization.WritingOptions.prettyPrinted)

        return self.client.request(codeExchangeUrl, method: .POST,  body: json, checkTokenExpiration: false, completionHandler: completionHandler)
    }
}
