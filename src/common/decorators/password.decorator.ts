import { ValidationArguments, ValidatorConstraint, ValidatorConstraintInterface, ValidatorOptions, registerDecorator, } from "class-validator";

export function ConfirmedPassword(property: string, validationOption?: ValidatorOptions) {
    return (object: any, propertyName: string) => {
        registerDecorator({
            target: object.constructor,
            propertyName,
            options: validationOption,
            constraints: [property],
            validator: ConfirmedPasswordConstrains,
        });
    };
}

@ValidatorConstraint({
    name: "ConfirmedPassword",
})
export class ConfirmedPasswordConstrains implements ValidatorConstraintInterface {
    validate(value: any, args?: ValidationArguments) {
        if (!args) {
            return false;
        }
        const { object, constraints } = args;
        const [property] = constraints;
        const relatedValue = object[property];
        return value === relatedValue;
    }
    defaultMessage(validationArguments?: ValidationArguments): string {
        return "تکرار رمز عبور باید برابر باشد";
    }
}