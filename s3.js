require("dotenv").config();
const fs = require("fs");
const S3 = require("aws-sdk/clients/s3");

const bucketName = "lolganeshbucket";
const region = "ap-south-1";
const accessKeyId = "AKIAQZW2F3GUIQL7IT6C";
const secretAccessKey = "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";
AWS_USER_PASSWORD = "6cmVZ6*-";

const s3 = new S3({
  region,
  accessKeyId,
  secretAccessKey,
});

// uploads a file to s3
function uploadFile(file) {
  const fileStream = fs.createReadStream(file.path);

  const uploadParams = {
    Bucket: bucketName,
    Body: fileStream,
    Key: file.filename,
  };

  return s3.upload(uploadParams).promise();
}
exports.uploadFile = uploadFile;

// downloads a file from s3
function getFileStream(fileKey) {
  const downloadParams = {
    Key: fileKey,
    Bucket: bucketName,
  };

  return s3.getObject(downloadParams).createReadStream();
}
exports.getFileStream = getFileStream;
