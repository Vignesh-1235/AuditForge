import JSZip from 'jszip';

/**
 * Recursively adds files or folders to a JSZip instance
 * @param {string} path - The relative path inside the zip
 * @param {File | File[]} fileEntry - The file(s) to add
 * @param {JSZip} zip - The JSZip instance
 */
const addFilesToZip = (path, fileEntry, zip) => {
    if (Array.isArray(fileEntry)) {
        fileEntry.forEach(file => {
            // If it's a file from dropzone, it usually has a `path` property
            const relativePath = file.path || file.name;
            // remove leading slash if any
            const cleanPath = relativePath.replace(/^\//, '');
            zip.file(cleanPath, file);
        });
    } else {
        zip.file(path, fileEntry);
    }
};

/**
 * Compresses an array of File objects (which may contain paths representing directories)
 * into a single JSZip Blob.
 * 
 * @param {File[]} files - The array of File objects to compress
 * @returns {Promise<Blob>} A promise that resolves to the compressed zip Blob
 */
export const compressFilesToZip = async (files) => {
    const zip = new JSZip();

    addFilesToZip("", files, zip);

    return await zip.generateAsync({ type: 'blob' });
};
