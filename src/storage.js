export const hasLocalStorageSupport = () => {
  const test = 'test'
  try {
    localStorage.setItem(test, test)
    localStorage.removeItem(test)
    return true
  } catch (e) {
    return false
  }
}

export const getFromLocalStorage = (key) => {
  try {
    return localStorage.getItem(key)
  } catch (err) {
    console.error(err)
    return undefined
  }
}

export const saveToLocalStorage = (key, value) => {
  try {
    localStorage.setItem(key, value)
  } catch (err) {
    console.error(err)
  }
}

export const loadJSONFromLocalStorage = (key) => {
  try {
    return JSON.parse(getFromLocalStorage(key))
  } catch (err) {
    console.error(err)
    return undefined
  }
}

export const saveJSONInLocalStorage = (key, value) => {
  try {
    saveToLocalStorage(key, JSON.stringify(value))
  } catch (err) {
    console.error(err)
  }
}
