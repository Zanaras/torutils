## v0.1.2
* Added `ext-json` as dependency.

## v0.1.1
* Onioo exits fetch is now functional
* Renamed fetch function to fetchExits
* Removed $withTime optional parameter
* Standardized use of $extra to mean "include any extra data we requested as this request if it exists"
* Removed use of formatList after parseOniooExitsList call -- since we have to parse the API call anyways, it's already in the correct format.
* Added error handling for parseOniooExitsList returning false from failing.
* Added `ext-curl` as dependency.

## v0.1.0
* Initial commit
* Added basic functionality.
* Not actually functional (sorry).
