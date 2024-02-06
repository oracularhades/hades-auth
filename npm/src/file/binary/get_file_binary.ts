function get_file_binary(file: any): Promise<any> {
    return new Promise((resolve, reject) => {
        var reader = new FileReader();
        reader.onload = function() {
            resolve(reader.result?.toString());
        }
        reader.readAsText(file);
    });
}

export default get_file_binary;