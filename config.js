module.exports = {
    DB: 'mongodb+srv://enzorh111:pcmongo111@cluster0.pzwnta5.mongodb.net/SD?appName=Cluster0',
    PORT: process.env.PORT || 4100,
    SECRET: 'miclavesecretadetokens',
    TOKEN_EXP_TIME: 7*24*60 // 7 días expresados en minutos
};