import express from "express";
import cors from "cors";
import { MongoClient, ObjectId } from "mongodb";
import dotenv from "dotenv";
import Joi from "joi";
import bcrypt from "bcrypt";
import { v4 as uuid } from "uuid";
import dayjs from "dayjs";

const app = express();

app.use(cors());
app.use(express.json());
dotenv.config();

const mongoClient = new MongoClient(process.env.DATABASE_URL);

try {
  await mongoClient.connect();
  console.log("MongoDB conectado!");
} catch (err) {
  (err) => console.log(err.message);
}

const db = mongoClient.db();

app.post("/cadastro", async (req, res) => {
  const { nome, email, senha } = req.body;

  const schema = Joi.object({
    nome: Joi.string().required(),
    email: Joi.string().email().required(),
    senha: Joi.string().min(3).required(),
    confirmaSenha: Joi.ref("senha"),
  });

  const validation = schema.validate(req.body, { abortEarly: false });

  if (validation.error) {
    console.log(validation.error.details);

    if (validation.error.details[0].type === "string.email") {
      return res.status(422).send("Email inválido!");
    }

    if (validation.error.details[0].type === "any.only") {
      return res.status(422).send("As senhas não conferem!");
    }

    if (validation.error.details[0].type === "string.min") {
      return res.status(422).send("A senha deve ter no mínimo 3 caracteres!");
    }

    return res.status(422).send("Dados inválidos!");
  }

  try {
    const userExists = await db.collection("users").findOne({ email });

    if (userExists) {
      return res.status(409).send("Email já cadastrado!");
    }

    await db
      .collection("users")
      .insertOne({ nome, email, senha: bcrypt.hashSync(senha, 10) });

    res.status(201).send("Usuário cadastrado com sucesso!");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post("/login", async (req, res) => {
  const { email, senha } = req.body;

  const schema = Joi.object({
    email: Joi.string().email().required(),
    senha: Joi.string().min(3).required(),
  });

  const validation = schema.validate(req.body, { abortEarly: false });

  if (validation.error) {
    if (validation.error.details[0].type === "string.email") {
      return res.status(422).send("Email inválido!");
    }

    if (validation.error.details[0].type === "string.min") {
      return res.status(422).send("A senha deve ter no mínimo 3 caracteres!");
    }
  }

  try {
    const userExists = await db.collection("users").findOne({ email });

    if (!userExists) {
      return res.status(404).send("Usuário não encontrado!");
    }

    if (!bcrypt.compareSync(senha, userExists.senha)) {
      return res.status(401).send("Senha incorreta!");
    }

    const tokenExists = await db
      .collection("sessao")
      .findOne({ idUsuario: userExists._id });

    if (tokenExists) {
      return res.status(404).send("Usuário já está logado!");
    }

    const token = uuid();
    await db
      .collection("sessao")
      .insertOne({ token, idUsuario: userExists._id });

    res.status(200).send({ token, nome: userExists.nome });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.post("/nova-transacao/:tipo", async (req, res) => {
  const { tipo } = req.params;
  const valor = parseFloat(req.body.valor);
  const { descricao } = req.body;
  const authorization = req.headers.authorization;
  const token = authorization?.replace("Bearer ", "");
  const data = dayjs().format("DD/MM");

  if (!token) {
    return res.status(401).send("Token não informado!");
  }

  const schema = Joi.object({
    valor: Joi.number().required(),
    descricao: Joi.string().required(),
  });

  const validation = schema.validate(req.body, { abortEarly: false });

  if (validation.error) {
    return res.status(422).send("Dados inválidos!");
  }

  try {
    const sessao = await db.collection("sessao").findOne({ token });
    if (!sessao) return res.sendStatus(401);

    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(sessao.idUsuario) });

    await db
      .collection("operacoes")
      .insertOne({ user: user.email, tipo, valor, descricao, data });

    res.status(201).send("Operação realizada com sucesso!");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.get("/extrato", async (req, res) => {
  const authorization = req.headers.authorization;
  const token = authorization?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).send("Token não informado!");
  }

  try {
    const sessao = await db.collection("sessao").findOne({ token });
    if (!sessao) return res.sendStatus(401);

    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(sessao.idUsuario) });

    const operacoes = await db
      .collection("operacoes")
      .find({ user: user.email })
      .toArray();

    res.status(200).send({ operacoes, nome: user.nome, id: user._id });
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.delete("/logout/:token", async (req, res) => {
  const { token } = req.params;

  try {
    await db.collection("sessao").deleteOne({ token });

    res.status(200).send("Logout realizado com sucesso!");
  } catch (err) {
    res.status(500).send(err.message);
  }
});

const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Servidor rodando na porta ${port}`);
});
