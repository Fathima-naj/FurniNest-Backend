
const Joi = require("joi");

const registerValidation = Joi.object({
  name: Joi.string()
    .trim()
    .min(2)
    .required()
    .messages({
      "string.empty": "Name is required.",
      "string.min": "Name must contain at least 2 characters.",
      "any.required": "Name is required.",
    }),

  // Optional for backward compatibility.
  // Backend will generate one when omitted.
  username: Joi.string()
    .trim()
    .min(4)
    .max(15)
    .pattern(/^[a-zA-Z0-9_]+$/)
    .optional()
    .messages({
      "string.min": "Username must be at least 4 characters.",
      "string.max": "Username must not exceed 15 characters.",
      "string.pattern.base":
        "Username can only contain letters, numbers and underscores.",
    }),

  email: Joi.string()
    .trim()
    .lowercase()
    .email()
    .required()
    .messages({
      "string.email": "Please enter a valid email address.",
      "string.empty": "Email is required.",
      "any.required": "Email is required.",
    }),

  password: Joi.string()
    .min(6)
    .required()
    .messages({
      "string.min": "Password must contain at least 6 characters.",
      "string.empty": "Password is required.",
    }),
});

const loginValidation = Joi.object({
  email: Joi.string()
    .trim()
    .lowercase()
    .email()
    .required()
    .messages({
      "string.email": "Please enter a valid email address.",
      "string.empty": "Email is required.",
    }),

  password: Joi.string()
    .required()
    .messages({
      "string.empty": "Password is required.",
    }),
});

module.exports = { registerValidation, loginValidation };
