import {Request, Response, Router} from "express";
import {EncryptedObject, EncryptionService} from "../services/encryptionService";
import {Base64Algorithm} from "../services/encryptionAlgorithm";
import {body, validationResult} from "express-validator";

const encryptionService = new EncryptionService(new Base64Algorithm());
export const encryptionRouter = Router();

// Middleware for validating schema of request body for /encrypt endpoint
const validateEncryptRequestBody = [
    // Validate req.body as a non-empty object
    body().custom((value) => {
        if (typeof value !== 'object' || value === null || Object.keys(value).length === 0) {
            throw new Error('Payload must be a non-empty object');
        }
        return true
    }),
];

// Middleware for validating schema of request body for /decrypt endpoint
const validateDecryptRequestBody = [
    // Validate req.body as a non-empty object
    body().custom((value) => {
        if (typeof value !== 'object' || value === null || Object.keys(value).length === 0) {
            throw new Error('Payload must be a non-empty object');
        }
        return true
    }),
];

/**
 * Endpoint POST /encrypt.
 * Encrypts the request body using the configured encryption algorithm.
 * @param {Request} req - The Express Request object.
 * @param {Response} res - The Express Response object.
 */
encryptionRouter.post('/encrypt', validateEncryptRequestBody, (req: Request, res: Response) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const encryptedPayload = encryptionService.encryptObject(req.body);
    res.json(encryptedPayload);
});

/**
 * Endpoint POST /decrypt.
 * Decrypts the request body using the configured encryption algorithm.
 * @param {Request} req - The Express Request object.
 * @param {Response} res - The Express Response object.
 */
encryptionRouter.post('/decrypt', validateDecryptRequestBody, (req: Request, res: Response) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const decryptedPayload = encryptionService.decryptObject(req.body as EncryptedObject);
    res.json(decryptedPayload);
});
