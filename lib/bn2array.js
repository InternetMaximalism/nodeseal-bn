export const arraySize = 60;

export function bn2array(bignum) {
  var numberArray = [];
  var interval = 2;
  var bignumString = bignum.toString();
  bignumString = "0"
    .repeat(arraySize * interval - bignumString.length)
    .concat(bignumString);
  for (let i = arraySize * interval; i - interval >= 0; i -= interval) {
    numberArray.push(parseInt(bignumString.slice(i - interval, i)));
  }
  return numberArray;
}
