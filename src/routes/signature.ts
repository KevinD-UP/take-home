import {Request, Response, Router} from "express";
import {Payload, SignatureService} from "../services/signatureService";
import {HashAlgorithmSha256} from "../services/hashAlgorithm";
import {body, validationResult} from "express-validator";

// Router for signature-related endpoints
export const signatureRouter = Router();
const signatureService = new SignatureService(new HashAlgorithmSha256())

// Middleware for validating schema of request body for /sign endpoint
const validateSignRequestBody = [
    // Validate req.body as a non-empty object
    body().custom((value) => {
        if (typeof value !== 'object' || value === null || Object.keys(value).length === 0) {
            throw new Error('Payload must be a non-empty object');
        }
        return true
    }),
];

// Middleware for validating schema of request body for /verify endpoint
const validateVerifyRequestBody = [
    // Validate req.body as a non-empty object
    body().custom((value) => {
        if (typeof value !== 'object' || value === null || Object.keys(value).length === 0) {
            throw new Error('Payload must be a non-empty object');
        }
        return true
    }),
    body('signature').isString().withMessage('Signature must be a string'),
    body('data').isObject().withMessage('Data must be an object'),
];


/**
 * POST /sign
 * Endpoint for generating an HMAC signature for the request body.
 * @param {Request} req - The Express Request object.
 * @param {Response} res - The Express Response object.
 */
signatureRouter.post('/sign', validateSignRequestBody, (req: Request, res: Response) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Generate HMAC signature for the request body
    const signature = signatureService.generateHmacSignature(req.body);
    res.json({signature});
});

/**
 * POST /verify
 * Endpoint for verifying an HMAC signature for the request body.
 * @param {Request} req - The Express Request object.
 * @param {Response} res - The Express Response object.
 */
signatureRouter.post('/verify', validateVerifyRequestBody, (req: Request, res: Response) => {
    // Check for validation errors
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    const {signature, data} = req.body as { signature: string, data: Payload };

    // Verify HMAC signature for the request body
    if (signatureService.verifyHmacSignature({signature, data})) {
        // If signature is valid, send a 204 (No Content) response
        res.sendStatus(204);
    } else {
        // If signature is invalid, send a 400 (Bad Request) response
        res.sendStatus(400);
    }
});
