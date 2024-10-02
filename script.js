(() => {
    const lengthSlider = document.getElementById('length');
    const lengthValue = document.getElementById('lengthValue');
    const lengthFeedback = document.getElementById('lengthFeedback');

    /**
     * Get strength feedback based on password length.
     * @param {number} length - The length of the password.
     * @returns {string} - "Weak" or "Strong" based on the length.
     */
    function getStrengthFeedback(length) {
        length = parseInt(length);
        if (length >= 6 && length <= 15) {
            return "Weak";
        } else if (length >= 16 && length <= 60) {
            return "Strong";
        } else {
            return "";
        }
    }

    // Set initial length value and feedback
    lengthValue.textContent = lengthSlider.value;
    lengthFeedback.textContent = getStrengthFeedback(lengthSlider.value);

    lengthSlider.addEventListener('input', () => {
        lengthValue.textContent = lengthSlider.value;
        lengthFeedback.textContent = getStrengthFeedback(lengthSlider.value);
    });

    /**
     * Secure random integer generator using rejection sampling to avoid modulo bias.
     * @param {number} max - The upper bound (exclusive).
     * @returns {number} - A cryptographically secure random integer between 0 and max - 1.
     */
    const getRandomInt = (max) => {
        const maxUint32 = 0xFFFFFFFF;
        const limit = maxUint32 - (maxUint32 % max);
        let randomValue;
        do {
            const array = new Uint32Array(1);
            window.crypto.getRandomValues(array);
            randomValue = array[0];
        } while (randomValue >= limit);
        return randomValue % max;
    };

    /**
     * Calculate the entropy of the password.
     * @param {number} passwordLength - The length of the password.
     * @param {number} characterSetSize - The size of the character set.
     * @returns {string} - The entropy in bits, formatted to two decimal places.
     */
    const calculateEntropy = (passwordLength, characterSetSize) => {
        return (passwordLength * Math.log2(characterSetSize)).toFixed(2);
    };

    /**
     * Determine the strength of the password based on entropy.
     * @param {number} entropy - The entropy of the password.
     * @returns {object} - An object containing the label and className for the strength indicator.
     */
    const getPasswordStrength = (entropy) => {
        if (entropy < 50) return { label: 'Weak', className: 'strength-weak' };
        if (entropy < 70) return { label: 'Fair', className: 'strength-fair' };
        if (entropy < 90) return { label: 'Good', className: 'strength-good' };
        if (entropy < 110) return { label: 'Strong', className: 'strength-strong' };
        if (entropy < 130) return { label: 'Very Strong', className: 'strength-very-strong' };
        if (entropy < 150) return { label: 'Extremely Strong', className: 'strength-extremely-strong' };
        return { label: 'Unbreakable', className: 'strength-unbreakable' };
    };

    /**
     * Display an error message to the user.
     * @param {string} message - The error message to display.
     */
    const displayError = (message) => {
        const errorMessage = document.getElementById('error-message');
        errorMessage.style.display = 'block';
        errorMessage.textContent = message;
    };

    /**
     * Clear any displayed error messages.
     */
    const clearError = () => {
        const errorMessage = document.getElementById('error-message');
        errorMessage.style.display = 'none';
        errorMessage.textContent = '';
    };

    /**
     * Show a toast notification with a message.
     * @param {string} message - The message to display in the toast.
     */
    const showToast = (message) => {
        const toast = document.getElementById('toast');
        toast.textContent = message;
        toast.className = 'toast show';
        setTimeout(() => {
            toast.className = 'toast';
        }, 3000);
    };

    /**
     * Build character sets based on user-selected options.
     * @param {object} options - The user-selected options.
     * @returns {Array} - An array of character sets.
     */
    const buildCharacterSets = (options) => {
        let characterSets = [];

        if (options.includeNumbers) {
            characterSets.push('0123456789');
        }
        if (options.includeLowercase) {
            characterSets.push('abcdefghijklmnopqrstuvwxyz');
        }
        if (options.includeUppercase) {
            characterSets.push('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
        }
        if (options.includeSymbols) {
            characterSets.push('!@#$%^&*()-_=+[]{}|;:",.<>/?~');
        }

        if (options.noSimilar) {
            const similarChars = /[il1Lo0O]/g;
            characterSets = characterSets.map(set => set.replace(similarChars, ''));
        }

        return characterSets;
    };

    /**
     * Ensure that at least one character from each selected character set is included.
     * @param {Array} passwordArray - The array to hold the password characters.
     * @param {Array} characterSets - The character sets selected by the user.
     * @param {object} options - The user-selected options.
     * @param {Set} usedChars - A set to track used characters.
     * @throws Will throw an error if it's impossible to include characters from all sets.
     */
    const ensureCharacterTypeInclusion = (passwordArray, characterSets, options, usedChars) => {
        characterSets.forEach(set => {
            const setArray = set.split('');
            let availableSetArray = setArray.slice();

            if (options.noDuplicate) {
                availableSetArray = availableSetArray.filter(char => !usedChars.has(char));
            }

            if (availableSetArray.length === 0) {
                throw new Error('Cannot include at least one character from each selected type due to the current settings. Adjust your settings.');
            }

            const char = availableSetArray[getRandomInt(availableSetArray.length)];
            passwordArray.push(char);
            usedChars.add(char);
        });
    };

    /**
     * Fill the rest of the password after ensuring character type inclusion.
     * @param {Array} passwordArray - The array holding the current password characters.
     * @param {Array} allCharsArray - The array of all available characters.
     * @param {number} length - The desired password length.
     * @param {object} options - The user-selected options.
     * @param {Set} usedChars - A set to track used characters.
     * @throws Will throw an error if it runs out of characters to use.
     */
    const fillPassword = (passwordArray, allCharsArray, length, options, usedChars) => {
        while (passwordArray.length < length) {
            if (allCharsArray.length === 0) {
                throw new Error('Ran out of characters to use. Adjust your settings or reduce the password length.');
            }

            const char = allCharsArray[getRandomInt(allCharsArray.length)];

            if (options.noDuplicate && usedChars.has(char)) {
                continue;
            }
            if (options.noSequential && passwordArray.length > 0) {
                const prevCharCode = passwordArray[passwordArray.length - 1].charCodeAt(0);
                const currCharCode = char.charCodeAt(0);
                if (Math.abs(currCharCode - prevCharCode) === 1) {
                    continue;
                }
            }

            passwordArray.push(char);
            usedChars.add(char);
        }
    };

    document.getElementById('generateBtn').addEventListener('click', () => {
        clearError();

        const length = parseInt(lengthSlider.value);
        const options = {
            includeNumbers: document.getElementById('includeNumbers').checked,
            includeLowercase: document.getElementById('includeLowercase').checked,
            includeUppercase: document.getElementById('includeUppercase').checked,
            includeSymbols: document.getElementById('includeSymbols').checked,
            noSimilar: document.getElementById('noSimilar').checked,
            noDuplicate: document.getElementById('noDuplicate').checked,
            noSequential: document.getElementById('noSequential').checked,
        };

        // Validate options
        if (!options.includeNumbers && !options.includeLowercase && !options.includeUppercase && !options.includeSymbols) {
            displayError('No character types selected. Please select at least one character type to include in your password.');
            return;
        }

        try {
            // Build character sets
            const characterSets = buildCharacterSets(options);

            // Build the complete character array
            let allCharsArray = characterSets.join('').split('');

            if (options.noDuplicate && length > allCharsArray.length) {
                displayError(`Cannot generate a ${length}-character password without duplicates given the selected options. Please reduce the password length or adjust your settings.`);
                return;
            }

            const passwordsContainer = document.getElementById('passwords');
            passwordsContainer.innerHTML = ''; // Clear previous passwords

            let generatedPasswords = new Set();
            let attempts = 0;

            while (generatedPasswords.size < 5 && attempts < 1000) {
                attempts++;

                let passwordArray = [];
                let usedChars = new Set();

                // Ensure at least one character from each selected character set
                ensureCharacterTypeInclusion(passwordArray, characterSets, options, usedChars);

                // Prepare available characters for filling the rest of the password
                let availableChars = allCharsArray.slice();

                if (options.noDuplicate) {
                    availableChars = availableChars.filter(char => !usedChars.has(char));
                }

                fillPassword(passwordArray, availableChars, length, options, usedChars);

                // Shuffle the password to mix the characters
                for (let i = passwordArray.length - 1; i > 0; i--) {
                    const j = getRandomInt(i + 1);
                    [passwordArray[i], passwordArray[j]] = [passwordArray[j], passwordArray[i]];
                }

                const password = passwordArray.join('');

                if (!generatedPasswords.has(password)) {
                    generatedPasswords.add(password);

                    // Calculate entropy for each password
                    const characterSetSize = allCharsArray.length;
                    const entropy = calculateEntropy(length, characterSetSize);
                    const strengthInfo = getPasswordStrength(entropy);

                    // Create a new div for each password
                    const passwordContainer = document.createElement('div');
                    passwordContainer.className = 'password-container';

                    const passwordText = document.createElement('div');
                    passwordText.className = 'password-text';
                    passwordText.textContent = password;

                    const passwordControls = document.createElement('div');
                    passwordControls.className = 'password-controls';

                    const strengthIndicator = document.createElement('div');
                    strengthIndicator.className = `strength-indicator ${strengthInfo.className}`;
                    strengthIndicator.textContent = `${strengthInfo.label} (${entropy} bits)`;

                    const copyBtn = document.createElement('button');
                    copyBtn.className = 'copy-btn';
                    copyBtn.textContent = 'Copy';

                    passwordControls.appendChild(strengthIndicator);
                    passwordControls.appendChild(copyBtn);

                    passwordContainer.appendChild(passwordText);
                    passwordContainer.appendChild(passwordControls);
                    passwordsContainer.appendChild(passwordContainer);

                    // Add copy functionality using Clipboard API
                    copyBtn.addEventListener('click', (e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(password).then(() => {
                            showToast('Password copied to clipboard!');
                        }).catch(err => {
                            showToast('Failed to copy password: ' + err);
                        });
                    });
                }
            }

            if (generatedPasswords.size < 5) {
                displayError('Could not generate enough unique passwords. Adjust your settings or reduce the password length.');
            }
        } catch (error) {
            displayError(error.message);
        }
    });
})();
