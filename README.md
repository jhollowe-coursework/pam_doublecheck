# pam_doublecheck
A linux PAM module to require approval for logons

## Setup

### Twilio Account and Project

Before the programs can be compiled, Twilio access credentials are needed to allow sending SMS messages.

Got to https://www.twilio.com/, click "Sign Up" and create an account. Then go to https://www.twilio.com/console/projects/create and create a project. You can choose any answer for the survey.

Once you have created a project, you will see your Account SID and Auth Token.  
If you are just testing this project, you can click the "Get a trial phone number" button to get a trial number to send from.

Once you have these values, replace the example values in `secrets.h` with your values.

### Compile and Install

To use this program, run `make`. This will create the `pam_doublecheck.so` and `doublecheck` files.  

Different distributions place PAM modules in different locations. To attempt to use the default location, run `sudo make install`.

If you get errors, you can manually find where PAM modules should be installed by running the command `find / -name pam_unix.so 2>/dev/null`. You can either manually copy the `pam_doublecheck.so` file to this location or you can change the `PAM_EXPORT_PATH` path in the `Makefile` to match your distribution (set the path to the result of the find command without the "pam_unix.so" at the end) and run `sudo make install` again.

## Usage

The pam_doublecheck.so module is only an `account` type PAM module. Attempting to use it as any other type of PAM module will cause unexpected behavior.

To add pam_doublecheck to a PAM flow, insert the following line into the relevant file in `/etc/pam.d/` (e.g. `/etc/pam.d/sudo`).

```
account required pam_doublecheck.so
```

For more information on configuring PAM, see The Linux Documentation Project's [detailed guide](https://tldp.org/HOWTO/User-Authentication-HOWTO/x115.html).

## Configuration

An example completely configured PAM module configuration line:

```
account required pam_doublecheck.so verifier_group=sudo bypass_group=sudo timeout=120 verified_need_percent=0.000001 verified_need_count=1
```

| Name               | Default  | Description                                                  | Usage                          |
|--------------------|----------|--------------------------------------------------------------|--------------------------------|
| Verifier Group     | sudo     | The group of users that are contacted to verify              | verifier_group=sudo            |
| Bypass Group       | sudo     | The group of users who do not require verification           | bypass_group=sudo              |
| Timeout            | 120      | The time (in seconds) to wait for verifiers                  | timeout=120                    |
| Minimum Percentage | 0.000001 | The percentage of verifiers needed to be considered verified | verified_need_percent=0.000001 |
| Minimum Count      | 1        | The number of verifiers needed to be considered verified     | verified_need_count=1          |

## Contributing

This project is not likely to receive continued development or support. Feel free to create an issue, but I am unlikely to do any debugging or fixes. If you would like to submit a pull request, I will consider merging it if the changes are beneficial and follow the spirit of the project.

Any code submitted should be formatted with clang format using the included `.clang-format` configuration file.

## References
* https://github.com/beatgammit/simple-pam
* https://github.com/google/google-authenticator-libpam
* https://github.com/TwilioDevEd/twilio_c_sms
