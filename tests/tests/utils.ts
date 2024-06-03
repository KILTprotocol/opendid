
export function addQueryParamsToUrl(url: URL, paramsObj: Record<string, string>): URL {
    let params = new URLSearchParams();

    for (let key in paramsObj) {
        if (paramsObj.hasOwnProperty(key)) {
            params.append(key, paramsObj[key]);
        }
    }
    return new URL(`${url}?${params.toString()}`);
}
