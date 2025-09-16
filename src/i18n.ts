import { I18nConfig, ErrorMessages, ErrorMessageKeys } from './types';

// Default error messages in English
const DEFAULT_MESSAGES: Record<string, Record<string, string>> = {
    en: {
        // Multi-login messages
        [ErrorMessageKeys.MULTI_LOGIN_DISABLED]: 'Multi-device login is disabled for this account',
        [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]: 'Previous sessions have been logged out due to new login',
        [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: 'Only one device can be logged in at a time',
        [ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED]: 'Maximum number of devices reached. Please log out from another device first',

        // General auth messages
        [ErrorMessageKeys.INVALID_TOKEN]: 'Invalid or malformed token',
        [ErrorMessageKeys.TOKEN_EXPIRED]: 'Token has expired. Please log in again',
        [ErrorMessageKeys.INVALID_CREDENTIALS]: 'Invalid email or password',
        [ErrorMessageKeys.ACCESS_DENIED]: 'Access denied. Insufficient permissions',
        [ErrorMessageKeys.RATE_LIMIT_EXCEEDED]: 'Too many requests. Please try again later',
        [ErrorMessageKeys.UNAUTHORIZED]: 'Unauthorized access',
        [ErrorMessageKeys.FORBIDDEN]: 'Access forbidden',
        [ErrorMessageKeys.NOT_FOUND]: 'Resource not found',
        [ErrorMessageKeys.INTERNAL_ERROR]: 'Internal server error'
    },
    es: {
        // Multi-login messages
        [ErrorMessageKeys.MULTI_LOGIN_DISABLED]: 'El inicio de sesión multi-dispositivo está deshabilitado para esta cuenta',
        [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]: 'Las sesiones anteriores han sido cerradas debido al nuevo inicio de sesión',
        [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: 'Solo se puede iniciar sesión en un dispositivo a la vez',
        [ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED]: 'Se alcanzó el número máximo de dispositivos. Por favor, cierre sesión en otro dispositivo primero',

        // General auth messages
        [ErrorMessageKeys.INVALID_TOKEN]: 'Token inválido o malformado',
        [ErrorMessageKeys.TOKEN_EXPIRED]: 'El token ha expirado. Por favor, inicie sesión nuevamente',
        [ErrorMessageKeys.INVALID_CREDENTIALS]: 'Email o contraseña inválidos',
        [ErrorMessageKeys.ACCESS_DENIED]: 'Acceso denegado. Permisos insuficientes',
        [ErrorMessageKeys.RATE_LIMIT_EXCEEDED]: 'Demasiadas solicitudes. Por favor, intente más tarde',
        [ErrorMessageKeys.UNAUTHORIZED]: 'Acceso no autorizado',
        [ErrorMessageKeys.FORBIDDEN]: 'Acceso prohibido',
        [ErrorMessageKeys.NOT_FOUND]: 'Recurso no encontrado',
        [ErrorMessageKeys.INTERNAL_ERROR]: 'Error interno del servidor'
    },
    fr: {
        // Multi-login messages
        [ErrorMessageKeys.MULTI_LOGIN_DISABLED]: 'La connexion multi-appareil est désactivée pour ce compte',
        [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]: 'Les sessions précédentes ont été fermées en raison de la nouvelle connexion',
        [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: 'Un seul appareil peut être connecté à la fois',
        [ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED]: 'Nombre maximum d\'appareils atteint. Veuillez vous déconnecter d\'un autre appareil d\'abord',

        // General auth messages
        [ErrorMessageKeys.INVALID_TOKEN]: 'Token invalide ou malformé',
        [ErrorMessageKeys.TOKEN_EXPIRED]: 'Le token a expiré. Veuillez vous reconnecter',
        [ErrorMessageKeys.INVALID_CREDENTIALS]: 'Email ou mot de passe invalide',
        [ErrorMessageKeys.ACCESS_DENIED]: 'Accès refusé. Permissions insuffisantes',
        [ErrorMessageKeys.RATE_LIMIT_EXCEEDED]: 'Trop de requêtes. Veuillez réessayer plus tard',
        [ErrorMessageKeys.UNAUTHORIZED]: 'Accès non autorisé',
        [ErrorMessageKeys.FORBIDDEN]: 'Accès interdit',
        [ErrorMessageKeys.NOT_FOUND]: 'Ressource non trouvée',
        [ErrorMessageKeys.INTERNAL_ERROR]: 'Erreur interne du serveur'
    },
    de: {
        // Multi-login messages
        [ErrorMessageKeys.MULTI_LOGIN_DISABLED]: 'Multi-Geräte-Anmeldung ist für dieses Konto deaktiviert',
        [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]: 'Vorherige Sitzungen wurden aufgrund der neuen Anmeldung beendet',
        [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: 'Nur ein Gerät kann gleichzeitig angemeldet sein',
        [ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED]: 'Maximale Anzahl von Geräten erreicht. Bitte melden Sie sich von einem anderen Gerät ab',

        // General auth messages
        [ErrorMessageKeys.INVALID_TOKEN]: 'Ungültiges oder fehlerhaftes Token',
        [ErrorMessageKeys.TOKEN_EXPIRED]: 'Token ist abgelaufen. Bitte melden Sie sich erneut an',
        [ErrorMessageKeys.INVALID_CREDENTIALS]: 'Ungültige E-Mail oder Passwort',
        [ErrorMessageKeys.ACCESS_DENIED]: 'Zugriff verweigert. Unzureichende Berechtigungen',
        [ErrorMessageKeys.RATE_LIMIT_EXCEEDED]: 'Zu viele Anfragen. Bitte versuchen Sie es später erneut',
        [ErrorMessageKeys.UNAUTHORIZED]: 'Unbefugter Zugriff',
        [ErrorMessageKeys.FORBIDDEN]: 'Zugriff verboten',
        [ErrorMessageKeys.NOT_FOUND]: 'Ressource nicht gefunden',
        [ErrorMessageKeys.INTERNAL_ERROR]: 'Interner Serverfehler'
    },
    pt: {
        // Multi-login messages
        [ErrorMessageKeys.MULTI_LOGIN_DISABLED]: 'Login multi-dispositivo está desabilitado para esta conta',
        [ErrorMessageKeys.PREVIOUS_SESSIONS_LOGGED_OUT]: 'Sessões anteriores foram encerradas devido ao novo login',
        [ErrorMessageKeys.SINGLE_DEVICE_ONLY]: 'Apenas um dispositivo pode estar logado por vez',
        [ErrorMessageKeys.DEVICE_LIMIT_EXCEEDED]: 'Número máximo de dispositivos atingido. Por favor, faça logout de outro dispositivo primeiro',

        // General auth messages
        [ErrorMessageKeys.INVALID_TOKEN]: 'Token inválido ou malformado',
        [ErrorMessageKeys.TOKEN_EXPIRED]: 'Token expirou. Por favor, faça login novamente',
        [ErrorMessageKeys.INVALID_CREDENTIALS]: 'Email ou senha inválidos',
        [ErrorMessageKeys.ACCESS_DENIED]: 'Acesso negado. Permissões insuficientes',
        [ErrorMessageKeys.RATE_LIMIT_EXCEEDED]: 'Muitas solicitações. Por favor, tente novamente mais tarde',
        [ErrorMessageKeys.UNAUTHORIZED]: 'Acesso não autorizado',
        [ErrorMessageKeys.FORBIDDEN]: 'Acesso proibido',
        [ErrorMessageKeys.NOT_FOUND]: 'Recurso não encontrado',
        [ErrorMessageKeys.INTERNAL_ERROR]: 'Erro interno do servidor'
    }
};

export class I18nManager {
    private locale: string;
    private messages: Record<string, Record<string, string>>;
    private fallbackLocale: string;

    constructor(config: I18nConfig = {}) {
        this.locale = config.locale || 'en';
        this.fallbackLocale = config.fallbackLocale || 'en';
        this.messages = { ...DEFAULT_MESSAGES, ...config.messages };
    }

    /**
     * Get a translated message
     */
    t(key: string, locale?: string): string {
        const targetLocale = locale || this.locale;

        // Try requested locale first
        if (this.messages[targetLocale] && this.messages[targetLocale][key]) {
            return this.messages[targetLocale][key];
        }

        // Fallback to default locale
        if (this.messages[this.fallbackLocale] && this.messages[this.fallbackLocale][key]) {
            return this.messages[this.fallbackLocale][key];
        }

        // Fallback to key itself
        return key;
    }

    /**
     * Get a translated message with interpolation
     */
    tWithParams(key: string, params: Record<string, string | number>, locale?: string): string {
        let message = this.t(key, locale);

        // Replace placeholders like {deviceId}, {count}, etc.
        Object.keys(params).forEach(param => {
            const placeholder = `{${param}}`;
            message = message.replace(new RegExp(placeholder, 'g'), String(params[param]));
        });

        return message;
    }

    /**
     * Set the current locale
     */
    setLocale(locale: string): void {
        this.locale = locale;
    }

    /**
     * Get the current locale
     */
    getLocale(): string {
        return this.locale;
    }

    /**
     * Add custom messages for a locale
     */
    addMessages(locale: string, messages: Record<string, string>): void {
        if (!this.messages[locale]) {
            this.messages[locale] = {};
        }
        this.messages[locale] = { ...this.messages[locale], ...messages };
    }

    /**
     * Get all available locales
     */
    getAvailableLocales(): string[] {
        return Object.keys(this.messages);
    }

    /**
     * Check if a locale is supported
     */
    isLocaleSupported(locale: string): boolean {
        return locale in this.messages;
    }
}

// Default i18n manager instance
export const defaultI18n = new I18nManager();
