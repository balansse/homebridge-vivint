const isObject = require("isobject")

function dataPatchArr(data, patch) {
  if (!Array.isArray(data)) {
    console.log("Expected to patch an array, got instead", typeof data)
    return false
  }
  for (let idx = 0; idx <= patch.length - 1; idx ++) {
    if (!(idx in data)) {
      console.log("invalid patch: idx not in data", idx)
      return false
    } else if (isObject(patch[idx])) {
      if (!dataPatchObj(data[idx], patch[idx]))
        return false
    } else {
      data[idx] = patch[idx]
    }
  }
  return true;
}

/**
 * Given {"a": {"b": 2, "c": 3}}, apply a patch of {"a.b", 1} results in {"a": {"b": 1, "c": 3}}
 *
 * Mutates in place
 */
function dataPatchObj(data, patch) {
  if (!isObject(data)) {
    console.log("Expected to patch an object, got instead", typeof data)
    return false
  }

  for (const key in patch) {
    const selector = key.split(".")
    if (selector.length > 1) {
      const head = selector.shift()
      const restPatch = {}
      restPatch[selector.join(".")] = patch[key]
      if(!dataPatchObj(data[head], restPatch))
        return(false)
    } else {
      if (patch[key] instanceof Array && Array.isArray(data[key])) {
        if (!dataPatchArr(data[key], patch[key]))
          return false
      } else {
        data[key] = patch[key]
      }
    }
  }
  return true;
}

module.exports = dataPatchObj
