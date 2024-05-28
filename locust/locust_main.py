from locustfiles import (ServiceRegistration, ClientRegistration, UserRegistration, OAuthUser, AuthorizationCodeFlow,
                         AuthorizationCodeFlowPKCE, ClientCredentialsFlow, RefreshTokenCRUD)
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
