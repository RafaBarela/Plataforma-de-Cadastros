from cadastroprodutos import database, login_manager
from datetime import datetime
from flask_login import UserMixin
import pytz
from datetime import datetime
from flask import current_app




def get_brasilia_time():
    brasilia_tz = pytz.timezone('America/Sao_Paulo')
    return datetime.now(brasilia_tz)

@login_manager.user_loader
def load_usuario(id_usuario):
    return Usuario.query.get(int(id_usuario))


class Usuario(database.Model, UserMixin):
    id = database.Column(database.Integer, primary_key=True)
    username = database.Column(database.String, nullable=False)
    email = database.Column(database.String, nullable=False, unique=True)
    senha = database.Column(database.String, nullable=False)
    role = database.Column(database.String, default='user')
    status = database.Column(database.String, default='pendente')
    ativo = database.Column(database.Boolean, default=True)



class Planilha(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    user_id = database.Column(database.Integer, database.ForeignKey('usuario.id'), nullable=False)
    solicitante = database.Column(database.String, nullable=False)
    descricao_material = database.Column(database.String, nullable=False)
    familia = database.Column(database.String, nullable=False)
    unidade_medida = database.Column(database.String, nullable=False)
    ncm = database.Column(database.String, nullable=False)
    projeto = database.Column(database.String(100), nullable=False)
    projeto_ficticio = database.Column(database.String(3), nullable=False)
    centro_custo = database.Column(database.Integer, nullable=False)
    cat_produto = database.Column(database.String(20), nullable=False)
    data = database.Column(database.DateTime, default=get_brasilia_time)
    status = database.Column(database.String(10), nullable=False, default='Pendente')
    codigo = database.Column(database.String(50), nullable=True)
    is_locked = database.Column(database.Boolean, default=False)
    n_solicitacao = database.Column(database.Integer, unique=True, nullable=False)
    tipo_material = database.Column(database.String(10), nullable=False)


    solicitante_usuario = database.relationship('Usuario', backref='planilhas')


class UnidadeMedida(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    nome = database.Column(database.String(50), unique=True, nullable=False)  # Abreviação (km, cm, etc.)
    descricao = database.Column(database.String(100), nullable=False)



class NCM(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    ncm = database.Column(database.String(20), unique=False, nullable=False)
    descricao_ncm = database.Column(database.Text, nullable=False)
    aliquota = database.Column(database.String(30), nullable=True)


    
class Familia(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    nome = database.Column(database.String, nullable=False)

    # Relacionamento com Material
    materiais = database.relationship(
        'Material',
        backref='familia',
        cascade="all, delete-orphan",
        lazy=True
    )


class Material(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    descricao = database.Column(database.String, nullable=False)
    familia_id = database.Column(database.Integer, database.ForeignKey('familia.id'), nullable=False)


class Destinatario(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    nome = database.Column(database.String(100), nullable=False)
    email = database.Column(database.String(100), unique=True, nullable=False)
    ativo = database.Column(database.Boolean, default=True)  # Define se o destinatário está ativo




class TipoProblema(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    nome = database.Column(database.String(200), unique=True, nullable=False)



class CadastroRNC(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    projeto = database.Column(database.String(100), nullable=False)
    cliente = database.Column(database.String(50), nullable=False)
    impacto_produto = database.Column(database.String(3), nullable=False)
    impacto_entrega = database.Column(database.String(3), nullable=False)
    impacto_financeiro = database.Column(database.Float, nullable=False)
    impacto_percepcao = database.Column(database.String(3), nullable=False)
    origem_setor = database.Column(database.String(50), nullable=False)
    solicitante = database.Column(database.String, nullable=True)
    email_solicitante = database.Column(database.String, nullable=False, unique=False)
    descricao_nc = database.Column(database.String(5000), nullable=False)
    plano_acao = database.Column(database.String(5000), nullable=True)
    centro_custo = database.Column(database.Integer, nullable=False)
    status_rnc = database.Column(database.String(10), nullable=False, default='Pendente')
    n_solicitacao = database.Column(database.Integer, unique=True, nullable=False)
    oc = database.Column(database.Integer, unique=False, nullable=False)  # Nova
    data_rnc = database.Column(database.DateTime, default=get_brasilia_time)
    usuario_id = database.Column(database.Integer, database.ForeignKey('usuario.id'), nullable=False)

    # Relacionamento com o modelo Usuario
    usuario = database.relationship('Usuario', backref='rncs', lazy=True)

    # Relacionamento com TipoProblema
    tipo_problema_id = database.Column(database.Integer, database.ForeignKey('tipo_problema.id'), nullable=False)
    tipo_problema = database.relationship('TipoProblema', backref='cadastros_rnc')



class ClienteRNC(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    nome = database.Column(database.String(50), nullable=False, unique=True)
    ativo = database.Column(database.Boolean, default=True)  # Para permitir a desativação de clientes



class CadastroFornecedores(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    anexo = database.Column(database.String(255), nullable=True)
    solicitante = database.Column(database.String, nullable=True)
    email_solicitante = database.Column(database.String, nullable=False, unique=False)
    nome = database.Column(database.String(100), nullable=False, unique=False) # Alterar Aqui
    cnpj = database.Column(database.String(30), nullable=False, unique=True)
    atividade_principal = database.Column(database.Text, nullable=False)
    atividades_secundarias = database.Column(database.Text, nullable=False)
    logradouro = database.Column(database.Text, nullable=False)
    numero = database.Column(database.String(10), nullable=False)
    complemento = database.Column(database.Text, nullable=True)
    municipio = database.Column(database.String(50), nullable=False)
    bairro = database.Column(database.String(50), nullable=False)
    uf = database.Column(database.String(2), nullable=False)
    cep = database.Column(database.String(8), nullable=False)
    email = database.Column(database.String(50), nullable=False)
    telefone = database.Column(database.String(50), nullable=True)
    inscricao_e = database.Column(database.String(20), nullable=True)
    regime_tributario = database.Column(database.String(100), nullable=True)
    status_cf = database.Column(database.String(10), nullable=True, default='Pendente')
    data_cadastro = database.Column(database.DateTime, default=get_brasilia_time)
    abertura = database.Column(database.String(10), nullable=True)
    situacao = database.Column(database.String(25), nullable=True)
    nome_fantasia = database.Column(database.String(100), nullable=True)
    cliente_tambem = database.Column(database.String(3), nullable=False)
    email_contato = database.Column(database.String(50), nullable=False)
    telefone_contato = database.Column(database.String(50), nullable=False)
    contato_pessoa = database.Column(database.String(50), nullable=False)
    n_solicitacao = database.Column(database.Integer, unique=True, nullable=False)
    banco = database.Column(database.String(100), unique=False, nullable=False)
    agencia = database.Column(database.String(6), unique=False, nullable=False)
    n_conta = database.Column(database.String(25), unique=False, nullable=False)
    tipo_conta = database.Column(database.String(15), unique=False, nullable=False)
    matriz_filial = database.Column(database.String(6), unique=False, nullable=False)
    email_contato2 = database.Column(database.String(50), nullable=False) # Nova
    usuario_id = database.Column(database.Integer, database.ForeignKey('usuario.id'), nullable=False)

    # Relacionamento com o modelo Usuario
    usuario = database.relationship('Usuario', backref='fornecedores', lazy=True)




class CadastroClientes(database.Model):
    id = database.Column(database.Integer, primary_key=True)
    solicitante = database.Column(database.String, nullable=True)
    email_solicitante = database.Column(database.String, nullable=False, unique=False)
    nome = database.Column(database.String(100), nullable=False, unique=False) # Alterar aqui
    cnpj = database.Column(database.String(30), nullable=False, unique=True)
    atividade_principal = database.Column(database.Text, nullable=False)
    atividades_secundarias = database.Column(database.Text, nullable=False)
    logradouro = database.Column(database.Text, nullable=False)
    numero = database.Column(database.String(10), nullable=False)
    complemento = database.Column(database.Text, nullable=True)
    municipio = database.Column(database.String(50), nullable=False)
    bairro = database.Column(database.String(50), nullable=False)
    uf = database.Column(database.String(2), nullable=False)
    cep = database.Column(database.String(8), nullable=False)
    email = database.Column(database.String(50), nullable=False)
    telefone = database.Column(database.String(100), nullable=True)
    inscricao_e = database.Column(database.String(20), nullable=True)
    regime_tributario = database.Column(database.String(100), nullable=True)
    status_cliente = database.Column(database.String(10), nullable=True, default='Pendente')
    data_cadastro = database.Column(database.DateTime, default=get_brasilia_time)
    abertura = database.Column(database.String(10), nullable=True)
    situacao = database.Column(database.String(25), nullable=True)
    nome_fantasia = database.Column(database.String(100), nullable=True)
    fornecedor_tambem = database.Column(database.String(3), nullable=False)
    email_contato = database.Column(database.String(50), nullable=False)
    telefone_contato = database.Column(database.String(50), nullable=False)
    n_solicitacao = database.Column(database.Integer, unique=True, nullable=False)
    contato_pessoa = database.Column(database.String(50), nullable=False)
    usuario_id = database.Column(database.Integer, database.ForeignKey('usuario.id'), nullable=False)

    # Relacionamento com o modelo Usuario
    usuario = database.relationship('Usuario', backref='clientesc', lazy=True)