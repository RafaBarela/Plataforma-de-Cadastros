from flask import render_template, redirect, url_for, flash, request, session, send_file, copy_current_request_context, current_app, abort
from cadastroprodutos import app, database, bcrypt, mail, scheduler, ALLOWED_EXTENSIONS
from cadastroprodutos.forms import FormLogin, FormCriarConta, UploadExcelForm
from cadastroprodutos.models import Usuario, Planilha, get_brasilia_time, UnidadeMedida, NCM, Material, Destinatario, Familia, CadastroRNC, TipoProblema, ClienteRNC, CadastroFornecedores, CadastroClientes
from flask_login import login_user, logout_user, current_user, login_required
from werkzeug.security import generate_password_hash
from threading import Thread
import threading
from flask import jsonify, send_from_directory
from sqlalchemy import or_, and_
from sqlalchemy.sql import func
import pandas as pd
from io import BytesIO
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask_mail import Message
from flask import current_app
from datetime import datetime, timedelta
import os
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.executors.pool import ThreadPoolExecutor
from zoneinfo import ZoneInfo
from cadastroprodutos.services import datetime_services
from itsdangerous import URLSafeTimedSerializer
import requests
import aiohttp
import asyncio
from werkzeug.utils import secure_filename



def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/')
def home():
    return render_template('home.html')


from flask_login import login_user, current_user


# Rota para login
@app.route('/login', methods=['GET', 'POST'])
def login():
    form_login = FormLogin()
    if form_login.validate_on_submit() and 'botao_submit_login' in request.form:
        usuario = Usuario.query.filter_by(email=form_login.email.data).first()

        if usuario:
            # Verificação do status do usuário antes do login
            if usuario.status != 'aprovado':
                if usuario.status == 'inativo':  # Verifica se a conta está inativa
                    flash('Sua conta está inativa. Entre em contato com o administrador.', 'alert-danger')
                else:  # Status pendente ou rejeitado
                    flash('Sua conta ainda não foi aprovada pelo administrador.', 'alert-warning')
                return redirect(url_for('login'))

            # Verificação de conta ativa
            if not usuario.ativo:
                flash('Sua conta está inativa. Entre em contato com o administrador.', 'alert-danger')
                return redirect(url_for('login'))

            # Exibir o hash e a senha para verificar o problema
            print("Hash armazenado no banco de dados:", usuario.senha)
            print("Senha fornecida para login:", form_login.senha.data)

            try:
                if bcrypt.check_password_hash(usuario.senha, form_login.senha.data):
                    login_user(usuario, remember=form_login.lembrar_dados.data)
                    flash(f'Login feito com sucesso no e-mail: {form_login.email.data}', 'alert-success')
                    par_next = request.args.get('next')
                    return redirect(par_next) if par_next else redirect(url_for('home'))
                else:
                    flash('Falha no Login. E-mail ou Senha Incorretos', 'alert-danger')
            except ValueError as e:
                print("Erro ao verificar o hash:", e)
                flash("Erro ao processar o login. Por favor, tente novamente.", 'alert-danger')
        else:
            flash('Falha no Login. Usuário não encontrado', 'alert-danger')

    return render_template('login.html', form_login=form_login)



# Rota para criar conta
@app.route('/criar_conta', methods=['GET', 'POST'])
def criar_conta():
    form_criarconta = FormCriarConta()

    if form_criarconta.validate_on_submit() and 'botao_submit_criarconta' in request.form:
        email = form_criarconta.email.data

        # Verificar se o email termina com "@riseretail.com"
        if not email.endswith("@riseretail.com"):
            flash("Endereço de email inválido!", 'alert-danger')
        else:
            # Gerar o hash da senha e garantir que seja uma string usando decode
            senha_cript = bcrypt.generate_password_hash(form_criarconta.senha.data).decode('utf-8')

            # Definir role com base no e-mail e status com base na primeira conta
            role = 'admin' if email in ['rafael.barela@riseretail.com', 'administrador@riseretail.com'] else 'user'
            status = 'aprovado' if email == 'rafael.barela@riseretail.com' and not Usuario.query.first() else 'pendente'

            # Criar o usuário com a role e o status adequados
            usuario = Usuario(username=form_criarconta.username.data, email=email, senha=senha_cript, role=role, status=status)
            database.session.add(usuario)
            database.session.commit()
            flash(f'Conta criada para o e-mail: {email}', 'alert-success')
            return redirect(url_for('login'))

    return render_template('criar_conta.html', form_criarconta=form_criarconta)



@app.route('/esqueceu_senha', methods=['GET', 'POST'])
def esqueceu_senha():
    if request.method == 'POST':
        email = request.form.get('email')
        usuario = Usuario.query.filter_by(email=email).first()

        if usuario:
            # Gerar um token para o usuário
            s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
            token = s.dumps(email, salt='recuperar-senha-salt')

            # Construir o link para redefinição de senha
            link = url_for('redefinir_senha', token=token, _external=True)

            # Criar a mensagem do e-mail
            msg = Message(
                subject='Recuperação de Senha',
                recipients=[email],
                body=f'Clique no link para redefinir sua senha: {link}'
            )

            # Enviar o e-mail de forma assíncrona
            send_async_email(msg)

            #flash('Um e-mail foi enviado com as instruções para redefinir sua senha.', 'success')
            return redirect(url_for('esqueceu_senha', enviado=True))
        else:
            flash('E-mail não encontrado.', 'danger')

    enviado = request.args.get('enviado', False)
    return render_template('esqueceu_senha.html', enviado=enviado)





@app.route('/redefinir_senha/<token>', methods=['GET', 'POST'])
def redefinir_senha(token):
    s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
    try:
        # Validar o token e extrair o e-mail
        email = s.loads(token, salt='recuperar-senha-salt', max_age=300)  # Token válido por 5 minutos
    except Exception as e:
        flash('O link de redefinição de senha é inválido ou expirou.', 'alert-danger')
        return redirect(url_for('esqueceu_senha'))

    if request.method == 'POST':
        nova_senha = request.form.get('senha')
        usuario = Usuario.query.filter_by(email=email).first()
        if usuario:
            usuario.senha = bcrypt.generate_password_hash(nova_senha).decode('utf-8')
            database.session.commit()
            flash('Sua senha foi redefinida com sucesso.', 'alert-success')
            return redirect(url_for('login'))
        else:
            flash('Erro ao redefinir a senha. Por favor, tente novamente.', 'alert-danger')

    return render_template('redefinir_senha.html', email=email)


@app.route('/editar_usuario', methods=['POST'])
@login_required
def editar_usuario():
    usuario_id = request.form.get('usuario_id')
    username = request.form.get('username')
    email = request.form.get('email')

    usuario = Usuario.query.get(usuario_id)
    if not usuario:
        flash("Usuário não encontrado.", "alert-danger")
        return redirect(url_for('admin_painel'))

    usuario.username = username
    usuario.email = email
    database.session.commit()

    flash("Usuário atualizado com sucesso!", "alert-success")
    return redirect(url_for('admin_painel'))




@app.route('/inativar_usuario/<int:id>', methods=['POST'])
@login_required
def inativar_usuario(id):
    usuario = Usuario.query.get(id)
    if not usuario:
        flash("Usuário não encontrado.", "alert-danger")
        return redirect(url_for('admin_painel'))

    usuario.status = 'inativo'
    database.session.commit()

    flash("Usuário inativado com sucesso!", "alert-warning")
    return redirect(url_for('admin_painel'))



from flask_login import current_user

@app.route('/cadastro', methods=['GET', 'POST'])
@login_required
def cadastro():
    unidades_medida = UnidadeMedida.query.all()
    ncms = NCM.query.all()

    if request.method == 'POST':
        user_id = current_user.id

        if user_id is None:
            return redirect(url_for('login'))

        usuario_atual = Usuario.query.get(user_id)
        if usuario_atual is None:
            flash("Usuário não encontrado.", "alert-danger")
            return redirect(url_for('login'))

        nome_solicitante = usuario_atual.username
        descricao_material = request.form.get('descricao_material').upper()
        familia = request.form.get('familia')
        unidade_medida = request.form.get('unidade_medida')
        ncm = request.form.get('ncm')
        projeto = request.form.get('projeto')
        centro_custo = request.form.get('centro_custo')
        cat_produto = request.form.get('cat_produto')
        projeto_ficticio = request.form.get('projeto_ficticio')
        tipo_material = request.form.get('tipo_material')  # Novo campo

        if not projeto_ficticio:
            return "Campo 'projeto_ficticio' é obrigatório", 400

        if tipo_material not in ['Nacional', 'Importado']:
            flash("O tipo de material deve ser 'Nacional' ou 'Importado'.", "alert-danger")
            return redirect(url_for('cadastro'))

        ncm_existente = NCM.query.filter_by(ncm=ncm).first()
        if not ncm_existente:
            flash("O NCM informado não existe no banco de dados. O produto não foi cadastrado.", "alert-danger")
            return redirect(url_for('cadastro'))

        ultimo_numero = database.session.query(database.func.max(Planilha.n_solicitacao)).scalar()
        novo_numero = (ultimo_numero or 0) + 1

        nova_solicitacao = Planilha(
            user_id=user_id,
            solicitante=nome_solicitante,
            descricao_material=descricao_material,
            familia=familia,
            unidade_medida=unidade_medida,
            ncm=ncm,
            projeto=projeto,
            centro_custo=centro_custo,
            cat_produto=cat_produto,
            projeto_ficticio=projeto_ficticio,
            tipo_material=tipo_material,  # Salva o novo campo
            data=datetime.utcnow(),
            n_solicitacao=novo_numero
        )

        database.session.add(nova_solicitacao)
        database.session.commit()

        return redirect(url_for('ver_planilhas'))

    return render_template('cadastro.html', unidades_medida=unidades_medida, ncms=ncms)


from datetime import datetime


@app.route('/ver_planilhas', methods=['GET', 'POST'])
@login_required
def ver_planilhas():
    # Obter os dados do formulário
    termo_pesquisa = request.form.get('termo_pesquisa', '').lower()
    status_filtro = request.form.get('status_filtro', '')
    projeto_ficticio_filtro = request.form.get('projeto_ficticio_filtro', '')
    data_inicial = request.form.get('data_inicial', '') or ''
    data_final = request.form.get('data_final', '') or ''
    familia_id = request.form.get('familia', '')  # Novo campo
    limpar_busca = request.form.get('limpar_busca')

    # Se o botão "Limpar Busca" for clicado, desconsidera os filtros
    if limpar_busca:
        termo_pesquisa = ''
        data_inicial = ''
        data_final = ''
        familia_id = ''
        status_filtro = ''  # Limpa o filtro de status
        projeto_ficticio_filtro = ''

    # Filtrar planilhas com base no termo de pesquisa
    query = Planilha.query
    if termo_pesquisa:
        query = query.filter(
            or_(
                Planilha.descricao_material.ilike(f"%{termo_pesquisa}%"),
                Planilha.projeto.ilike(f"%{termo_pesquisa}%"),
                Planilha.solicitante.ilike(f"%{termo_pesquisa}%"),
                Planilha.ncm.ilike(f"%{termo_pesquisa}%"),
                Planilha.codigo.ilike(f"%{termo_pesquisa}%"),
                Planilha.status.ilike(f"%{termo_pesquisa}%"),
                Planilha.projeto_ficticio.ilike(f"%{termo_pesquisa}%")
            )
        )

    # Filtro por Status
    if status_filtro:
        query = query.filter(Planilha.status == status_filtro)

    # Filtro por Projeto Fictício
    if projeto_ficticio_filtro:
        query = query.filter(Planilha.projeto_ficticio == projeto_ficticio_filtro)

    # Filtrar por data ou intervalo de datas, se fornecido
    if data_inicial or data_final:
        try:
            if data_inicial:
                data_inicial = datetime.strptime(data_inicial, '%d/%m/%Y')
            if data_final:
                # Incluir o final do dia
                data_final = datetime.strptime(data_final, '%d/%m/%Y') + timedelta(days=1) - timedelta(seconds=1)

            if data_inicial and data_final:
                # Filtrar por intervalo de datas
                query = query.filter(Planilha.data.between(data_inicial, data_final))
            elif data_inicial:
                # Filtrar por uma única data (data_inicial), desconsiderando o horário
                query = query.filter(func.date(Planilha.data) == data_inicial.date())
        except ValueError:
            flash('Formato de data inválido. Use DD/MM/AAAA.', 'danger')

    # Filtrar por Família, se fornecida
    if familia_id:
        query = query.filter(Planilha.familia == familia_id)

    # Executar a consulta final
    planilhas = query.all()

    # Buscar o mapeamento de famílias do banco de dados
    familias = {familia.id: familia.nome for familia in Familia.query.all()}

    # Substituir valores da família e 'projeto_ficticio' conforme o mapeamento
    for planilha in planilhas:
        if planilha.familia.isdigit():
            planilha.familia = familias.get(int(planilha.familia), planilha.familia)

        planilha.data_formatada = datetime_services.to_brasilia_time(planilha.data).strftime(
            '%d/%m/%Y %H:%M:%S') if planilha.data else 'Data não disponível'

    return render_template(
        'ver_planilhas.html',
        planilhas=planilhas,
        familias=familias,  # Passar famílias para preencher o dropdown
        termo_pesquisa=termo_pesquisa,
        data_inicial=data_inicial,
        data_final=data_final,
        familia_id=familia_id,  # Manter o valor selecionado no formulário
        status_filtro=status_filtro,  # Passar status_filtro para manter o estado no formulário
        projeto_ficticio_filtro=projeto_ficticio_filtro  # Passar projeto_ficticio_filtro
    )




@app.route('/sair')
@login_required
def sair():
    logout_user()
    flash(f'Logout Feito com Sucesso', 'alert-success')
    return redirect(url_for('home'))



@app.route('/admin/painel')
def admin_painel():
    if current_user.role != 'admin':
        return redirect(url_for('home'))
    usuarios = Usuario.query.all()
    return render_template('admin.html', usuarios=usuarios)




@app.route('/alterar_status_usuario/<int:id>', methods=['POST'])
@login_required
def alterar_status_usuario(id):
    if current_user.role != 'admin':
        flash('Apenas administradores podem alterar o status dos usuários.', 'alert-danger')
        return redirect(url_for('painel_adm'))

    usuario = Usuario.query.get_or_404(id)
    usuario.status = request.form['status']
    database.session.commit()
    flash(f'O status do usuário {usuario.username} foi alterado para {usuario.status}.', 'alert-success')
    return redirect(url_for('admin_painel'))


@app.route('/alterar_ativo_usuario/<int:id>', methods=['POST'])
@login_required
def alterar_ativo_usuario(id):
    if current_user.role != 'admin':
        flash('Apenas administradores podem alterar o status de ativação dos usuários.', 'alert-danger')
        return redirect(url_for('painel_adm'))

    usuario = Usuario.query.get_or_404(id)

    # Alterna o estado de ativo/inativo
    usuario.ativo = not usuario.ativo

    database.session.commit()
    status_ativo = 'ativo' if usuario.ativo else 'inativo'
    flash(f'O usuário {usuario.username} foi alterado para {status_ativo}.', 'alert-success')
    return redirect(url_for('admin_painel'))



@app.route('/admin/upload_ncm', methods=['GET', 'POST'])
def upload_ncm():
    # Verifica se o usuário tem permissão para processar o arquivo
    allowed_users = ['rafael.barela@riseretail.com', 'administrador@riseretail.com']
    user_has_permission = current_user.is_authenticated and current_user.email in allowed_users

    ncm_atual = None  # Variável para armazenar o NCM buscado
    mensagem_erro = None  # Variável para erros específicos

    if request.method == 'POST' and user_has_permission:
        # Caso o formulário seja para processar o arquivo
        if 'processar_arquivo' in request.form:
            upload_dir = 'cadastroprodutos/documentos'
            filepath = os.path.join(upload_dir, 'ncms.xlsx')

            try:
                # Lê o arquivo e processa os dados
                df = pd.read_excel(filepath)

                # Verifica se as colunas necessárias estão no arquivo
                if set(['ncm', 'descricao_ncm', 'aliquota']).issubset(df.columns):
                    novos_ncms = 0  # Contador de novos registros
                    registros_excluidos = 0  # Contador de registros removidos
                    alíquotas_atualizadas = 0  # Contador de alíquotas atualizadas

                    # Extrair todos os NCMs do arquivo Excel
                    ncms_do_excel = set(df['ncm'].astype(str))  # Garantir que todos sejam strings

                    with app.app_context():
                        # Obter todos os NCMs do banco de dados
                        ncms_no_banco = {ncm.ncm: ncm for ncm in NCM.query.all()}  # Mapeia NCM para o objeto NCM

                        # Identificar NCMs a serem excluídos (presentes no banco, mas não no Excel)
                        ncms_para_excluir = set(ncms_no_banco.keys()) - ncms_do_excel

                        # Excluir NCMs que não estão no Excel
                        if ncms_para_excluir:
                            NCM.query.filter(NCM.ncm.in_(ncms_para_excluir)).delete(synchronize_session=False)
                            registros_excluidos = len(ncms_para_excluir)

                        # Adicionar novos NCMs e atualizar alíquotas
                        for index, row in df.iterrows():
                            ncm = row['ncm']
                            descricao = row['descricao_ncm']
                            aliquota = row['aliquota']

                            if ncm in ncms_no_banco:
                                # NCM já existe, verifica se precisa atualizar a alíquota
                                ncm_obj = ncms_no_banco[ncm]
                                if ncm_obj.aliquota != aliquota:  # Atualiza se a alíquota for diferente
                                    ncm_obj.aliquota = aliquota
                                    alíquotas_atualizadas += 1
                            else:
                                # Adiciona um novo NCM
                                novo_ncm = NCM(
                                    ncm=ncm,
                                    descricao_ncm=descricao,
                                    aliquota=aliquota
                                )
                                database.session.add(novo_ncm)
                                novos_ncms += 1

                        # Confirmar alterações no banco
                        database.session.commit()

                    # Mensagens de feedback
                    flash(f"""
                        {novos_ncms} novos registros adicionados, 
                        {registros_excluidos} registros removidos, 
                        {alíquotas_atualizadas} alíquotas atualizadas.
                    """, 'alert-success')

                else:
                    flash('Erro: O arquivo não contém as colunas necessárias', 'alert-danger')
            except Exception as e:
                flash(f'Erro ao processar o arquivo: {e}', 'alert-danger')

        # Caso o formulário seja para editar um NCM
        elif 'editar_ncm' in request.form:
            ncm_id = request.form.get('ncm_id')
            nova_aliquota = request.form.get('nova_aliquota')
            nova_descricao = request.form.get('nova_descricao')

            try:
                ncm_atual = NCM.query.get(ncm_id)
                if ncm_atual:
                    ncm_atual.aliquota = nova_aliquota
                    ncm_atual.descricao_ncm = nova_descricao
                    database.session.commit()
                    flash('NCM atualizado com sucesso!', 'alert-success')
                else:
                    mensagem_erro = 'NCM não encontrado.'
            except Exception as e:
                mensagem_erro = f'Erro ao atualizar o NCM: {e}'

        # Caso o formulário seja para buscar um NCM
        elif 'buscar_ncm' in request.form:
            ncm_codigo = request.form.get('ncm_buscar')
            ncm_atual = NCM.query.filter_by(ncm=ncm_codigo).first()
            if not ncm_atual:
                mensagem_erro = 'NCM não encontrado.'

    return render_template('upload_ncm.html',
                           user_has_permission=user_has_permission,
                           ncm_atual=ncm_atual,
                           mensagem_erro=mensagem_erro)



@app.route('/alterar_funcao/<int:id>', methods=['POST'])
@login_required
def alterar_funcao(id):
    if current_user.role != 'admin':  # Verifica se o usuário atual é admin
        return redirect(url_for('home'))

    usuario = Usuario.query.get(id)
    novo_role = request.form.get('role')

    if usuario:
        # Verifica se o novo papel é válido
        if novo_role in ['user', 'admin']:
            usuario.role = novo_role  # Atualiza o papel do usuário
            database.session.commit()

    return redirect(url_for('admin_painel'))  # Corrigido para admin_painel



@app.route('/admin/unidade_medida', methods=['GET', 'POST'])
@login_required
def adicionar_unidade_medida():
    if current_user.role != 'admin':  # Verifica se o usuário é admin
        flash("Você não tem permissão para acessar essa página.", "alert-danger")
        return redirect(url_for('home'))

    if request.method == 'POST':
        nova_unidade = request.form.get('nova_unidade')
        descricao_unidade = request.form.get('descricao_unidade')  # Captura a descrição

        if nova_unidade and descricao_unidade:
            # Verificar se já existe a unidade de medida
            unidade_existente = UnidadeMedida.query.filter_by(nome=nova_unidade).first()
            if unidade_existente:
                flash("Essa unidade de medida já existe.", "alert-warning")
            else:
                # Cria uma nova unidade de medida com nome e descrição
                nova_unidade_medida = UnidadeMedida(nome=nova_unidade, descricao=descricao_unidade)
                database.session.add(nova_unidade_medida)
                database.session.commit()
                flash("Nova unidade de medida adicionada com sucesso!", "alert-success")
                return redirect(url_for('adicionar_unidade_medida'))

    unidades_medida = UnidadeMedida.query.all()  # Lista todas as unidades existentes
    return render_template('adicionar_unidade_medida.html', unidades=unidades_medida)



@app.route('/deletar_usuario/<int:id>', methods=['POST'])
@login_required
def deletar_usuario(id):
    if current_user.role != 'admin':  # Verifica se o usuário atual é admin
        return redirect(url_for('home'))

    usuario = Usuario.query.get(id)
    if usuario:
        database.session.delete(usuario)  # Remove o usuário
        database.session.commit()  # Salva as mudanças

    return redirect(url_for('admin_painel'))  # Redireciona para o painel administrativo


@app.route('/atualizar_status', methods=['POST'])
@login_required
def atualizar_status():
    data = request.get_json()
    planilha_id = data.get('planilha_id')
    novo_status = data.get('status')
    novo_codigo = data.get('codigo')
    motivo_rejeicao = data.get('motivo_rejeicao', '')

    if current_user.role != 'admin':
        return jsonify({'error': 'Acesso negado'}), 403

    planilha = Planilha.query.get(planilha_id)
    if planilha:
        if planilha.is_locked:
            return jsonify({'error': 'A planilha está bloqueada e não pode ser editada.'}), 400

        planilha.status = novo_status
        if novo_status == 'Aprovado' and not novo_codigo:
            return jsonify({'error': 'O campo Código é obrigatório quando o status é Aprovado.'}), 400

        if novo_codigo is not None:
            planilha.codigo = novo_codigo

        if novo_status in ['Aprovado', 'Rejeitado']:
            planilha.is_locked = True

        database.session.commit()

        # Enviar e-mail ao solicitante de forma assíncrona
        if novo_status == 'Aprovado':
            enviar_email_aprovacao(
                codigo=planilha.codigo,
                solicitante_email=planilha.solicitante_usuario.email,
                descricao_material=planilha.descricao_material,
                n_solicitacao=planilha.n_solicitacao  # Adicionando o número da solicitação
            )
        elif novo_status == 'Rejeitado':
            enviar_email_rejeicao(
                email_destino=planilha.solicitante_usuario.email,
                motivo_rejeicao=motivo_rejeicao,
                descricao_material=planilha.descricao_material,
                n_solicitacao=planilha.n_solicitacao  # Adicionando o número da solicitação
            )

        return jsonify({'success': 'Status atualizado com sucesso! E-mail enviado.'})
    else:
        return jsonify({'error': 'Planilha não encontrada'}), 404



def async_send_email(app, msg):
    with app.app_context():
        mail.send(msg)


def send_async_email(msg):
    app = current_app._get_current_object()
    thr = Thread(target=async_send_email, args=[app, msg])
    thr.start()


# Função para enviar e-mail de aprovação
def enviar_email_aprovacao(codigo, solicitante_email, descricao_material, n_solicitacao):
    msg = Message(f"Aprovação da Solicitação #{n_solicitacao}", recipients=[solicitante_email])

    # Usando HTML no corpo do e-mail, com o código em negrito
    msg.html = f"""
    <p>Sua solicitação foi aprovada.</p>
    <p><strong>Número da Solicitação:</strong> {n_solicitacao}</p>
    <p><strong>Código:</strong> {codigo}</p>
    <p><strong>Descrição do Material:</strong> {descricao_material}</p>
    """

    # Enviar o e-mail de forma assíncrona
    send_async_email(msg)


def enviar_email_rejeicao(email_destino, motivo_rejeicao, descricao_material, n_solicitacao):
    msg = Message(f"Rejeição da Solicitação #{n_solicitacao}", recipients=[email_destino])

    # Usando HTML no corpo do e-mail, com motivo em negrito
    msg.html = f"""
    <p>Sua solicitação foi rejeitada.</p>
    <p><strong>Número da Solicitação:</strong> {n_solicitacao}</p>
    <p><strong>Motivo:</strong> {motivo_rejeicao}</p>
    <p><strong>Descrição do Material:</strong> {descricao_material}</p>
    """

    # Enviar o e-mail de forma assíncrona
    send_async_email(msg)



@app.route('/exportar_excel', methods=['POST'])
def exportar_excel():
    dados = request.json
    ids_selecionados = dados.get('ids', [])

    # Supondo que você tenha um banco de dados com as planilhas
    planilhas_selecionadas = Planilha.query.filter(Planilha.id.in_(ids_selecionados)).all()

    # Criar DataFrame com as planilhas selecionadas
    data = [{
        "Solicitante": planilha.solicitante,
        "Descrição Material": planilha.descricao_material,
        "Família": planilha.familia,
        "Unidade de Medida": planilha.unidade_medida,
        "NCM": planilha.ncm,
        "Data": planilha.data.strftime('%d/%m/%Y %H:%M:%S'),
        "Status": planilha.status
    } for planilha in planilhas_selecionadas]

    # Gerar o arquivo Excel
    df = pd.DataFrame(data)
    output = BytesIO()
    with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
        df.to_excel(writer, index=False, sheet_name='Solicitações')
    output.seek(0)

    # Enviar o arquivo para o download
    return send_file(output, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                     as_attachment=True, download_name='exportacao.xlsx')


@app.route('/enviar_email', methods=['POST'])
@login_required
def enviar_email():
    try:
        # Buscar destinatários ativos no banco de dados
        destinatarios = [dest.email for dest in Destinatario.query.filter_by(ativo=True).all()]

        assunto = "Nova Solicitação de Cadastro"
        corpo_email = f"""
        <p>Uma nova solicitação de cadastro foi realizada no sistema por <strong>{current_user.username}</strong>.</p>
        <p>Por favor, acesse o sistema para revisar a solicitação.</p>
        """

        msg = Message(
            subject=assunto,
            sender="Solicitação de Material <administrador@riseretail.com>",
            recipients=destinatarios,
            reply_to=current_user.email,
        )

        msg.html = corpo_email
        send_async_email(msg)  # Envia o e-mail de forma assíncrona

        return jsonify({'success': True, 'message': 'E-mail enviado com sucesso!'})
    except Exception as e:
        print("Erro ao enviar e-mail:", e)
        return jsonify({'success': False, 'error': str(e)})





@app.route('/get_familias', methods=['GET'])
def get_familias():
    familias = Familia.query.all()
    return jsonify([{"id": familia.id, "nome": familia.nome} for familia in familias])


@app.route('/get_materiais/<int:familia_id>', methods=['GET'])
def get_materiais(familia_id):
    materiais = Material.query.filter_by(familia_id=familia_id).all()
    return jsonify([{"id": material.id, "descricao": material.descricao} for material in materiais])



@app.route('/admin/destinatarios', methods=['GET', 'POST'])
@login_required
def gerenciar_destinatarios():
    # Verifica se o usuário tem a role 'admin'
    if current_user.role != 'admin':
        abort(403)  # Retorna um erro 403 se o usuário não for admin

    if request.method == 'POST':
        nome = request.form['nome']
        email = request.form['email']

        # Verifica se o email está cadastrado na tabela Usuario
        if not Usuario.query.filter_by(email=email).first():
            flash('O email não está registrado no sistema.', 'alert-danger')
            return redirect(url_for('gerenciar_destinatarios'))

        destinatario = Destinatario(nome=nome, email=email)
        database.session.add(destinatario)
        database.session.commit()
        flash('Destinatário adicionado com sucesso.', 'alert-success')

    destinatarios = Destinatario.query.all()
    return render_template('admin_destinatarios.html', destinatarios=destinatarios)



@app.route('/admin/destinatarios/remover/<int:id>', methods=['POST'])
@login_required
def remover_destinatario(id):
    destinatario = Destinatario.query.get_or_404(id)
    database.session.delete(destinatario)
    database.session.commit()
    flash('Destinatário removido com sucesso.', 'alert-success')
    return redirect(url_for('gerenciar_destinatarios'))



@app.route('/adicionar_familia', methods=['POST'])
@login_required
def adicionar_familia():
    nome_familia = request.form.get('nome_familia', '').strip()

    if not nome_familia:
        flash("O nome da família não pode estar vazio.", "alert-danger")
        return redirect(url_for('gerenciar_cadastros'))

    # Validação Verificar se o nome está em maiusculo
    if nome_familia != nome_familia.upper():
        flash("O nome da família deve estar todo em maiúsculas.", "alert-danger")
        return redirect(url_for('gerenciar_cadastros'))

    # Verificar se a família já existe (insensível a maiúsculas/minúsculas)
    if Familia.query.filter(Familia.nome.ilike(nome_familia)).first():
        flash("Essa família já existe.", "alert-warning")
        return redirect(url_for('gerenciar_cadastros'))

    # Adicionar nova família
    nova_familia = Familia(nome=nome_familia)
    database.session.add(nova_familia)
    database.session.commit()

    flash("Família adicionada com sucesso!", "alert-success")
    return redirect(url_for('gerenciar_cadastros'))


@app.route('/editar_familia/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_familia(id):
    familia = Familia.query.get_or_404(id)

    if request.method == 'POST':
        nome_familia = request.form.get('nome_familia', '').strip()

        if not nome_familia:
            flash("O nome da família não pode estar vazio.", "alert-danger")
            return redirect(url_for('gerenciar_cadastros'))

        if nome_familia != nome_familia.upper():
            flash("O nome da família deve estar todo em maiúsculas.", "alert-danger")
            return redirect(url_for('gerenciar_cadastros'))

        familia.nome = nome_familia
        database.session.commit()
        flash("Família editada com sucesso!", "alert-success")
        return redirect(url_for('gerenciar_cadastros'))

    return render_template('editar_familia.html', familia=familia)



@app.route('/remover_familia/<int:id>', methods=['POST'])
@login_required
def remover_familia(id):
    if current_user.role != 'admin':
        flash("Acesso negado.", "alert-danger")
        return redirect(url_for('home'))

    familia = Familia.query.get_or_404(id)

    if familia.materiais:
        flash("Não é possível remover uma família que possui materiais associados.", "alert-danger")
        return redirect(url_for('gerenciar_cadastros'))

    database.session.delete(familia)
    database.session.commit()
    flash("Família removida com sucesso!", "alert-success")
    return redirect(url_for('gerenciar_cadastros'))




@app.route('/adicionar_material', methods=['POST'])
@login_required
def adicionar_material():
    descricao_material = request.form.get('descricao_material')
    familia_id = request.form.get('familia_id')

    if not descricao_material or not familia_id:
        flash("Todos os campos são obrigatórios.", "alert-danger")
        return redirect(url_for('gerenciar_cadastros'))

    # Verificar se a família existe
    familia = Familia.query.get(familia_id)
    if not familia:
        flash("Família selecionada não encontrada.", "alert-danger")
        return redirect(url_for('gerenciar_cadastros'))

    # Adicionar novo material
    novo_material = Material(descricao=descricao_material, familia_id=familia_id)
    database.session.add(novo_material)
    database.session.commit()

    flash("Material adicionado com sucesso!", "alert-success")
    return redirect(url_for('gerenciar_cadastros'))



@app.route('/remover_material/<int:id>', methods=['POST'])
@login_required
def remover_material(id):
    material = Material.query.get_or_404(id)

    database.session.delete(material)
    database.session.commit()

    flash("Material removido com sucesso!", "alert-success")
    return redirect(url_for('gerenciar_cadastros'))




@app.route('/gerenciar_cadastros', methods=['GET', 'POST'])
@login_required
def gerenciar_cadastros():
    if current_user.role != 'admin':  # Verifica se o usuário é um administrador
        flash("Acesso negado.", "alert-danger")
        return redirect(url_for('home'))

    # Carregar todas as famílias e materiais para exibição
    familias = Familia.query.all()
    materiais = Material.query.all()  # Carrega os materiais

    if request.method == 'POST':
        tipo_cadastro = request.form.get('tipo_cadastro')  # 'familia' ou 'material'

        if tipo_cadastro == 'familia':
            # Adicionar nova família
            nome_familia = request.form.get('nome_familia')
            if nome_familia:
                nova_familia = Familia(nome=nome_familia)
                database.session.add(nova_familia)
                database.session.commit()
                flash("Família adicionada com sucesso!", "alert-success")
            else:
                flash("O nome da família é obrigatório.", "alert-danger")

        elif tipo_cadastro == 'material':
            # Adicionar novo material
            descricao_material = request.form.get('descricao_material')
            familia_id = request.form.get('familia_id')
            if descricao_material and familia_id:
                novo_material = Material(descricao=descricao_material, familia_id=familia_id)
                database.session.add(novo_material)
                database.session.commit()
                flash("Material adicionado com sucesso!", "alert-success")
            else:
                flash("A descrição e a família do material são obrigatórias.", "alert-danger")

        return redirect(url_for('gerenciar_cadastros'))

    return render_template('gerenciar_cadastros.html', familias=familias, materiais=materiais)  # Passando os materiais também



def verificar_pendentes_e_enviar_email():
    """Verifica solicitações pendentes há mais de 24 horas e dispara e-mails."""
    with current_app.app_context():  # Garante o contexto
        vinte_e_quatro_horas_atras = datetime.utcnow() - timedelta(hours=24)

        # Busca solicitações pendentes há mais de 5 minutos
        pendentes = Planilha.query.filter(
            Planilha.status == 'Pendente',
            Planilha.data <= vinte_e_quatro_horas_atras
        ).all()

        if not pendentes:
            print("Nenhuma solicitação pendente encontrada.")
            return

        destinatario_fixo = "gleydson.nascimento@riseretail.com"


        for planilha in pendentes:
            try:
                # Atualiza o status antes de enviar o e-mail
                planilha.status = 'Notificado'
                database.session.commit()

                print(f"Enviando e-mail para pendência de {planilha.solicitante}")
                assunto = f"Alerta: Solicitação pendente de {planilha.solicitante}"
                corpo_email = f"""
                <p>A solicitação de cadastro realizada por <strong>{planilha.solicitante}</strong> está pendente há mais de 5 minutos.</p>
                <p>Descrição do Material: {planilha.descricao_material}</p>
                <p>Por favor, acesse o sistema para revisar a solicitação.</p>
                """
                msg = Message(
                    subject=assunto,
                    sender="Solicitação de Material <administrador@riseretail.com>",
                    recipients=[destinatario_fixo]
                )
                msg.html = corpo_email
                mail.send(msg)
                print(f"E-mail enviado para {planilha.solicitante}")
            except Exception as e:
                # Reverter a alteração no status se falhar
                planilha.status = 'Pendente'
                database.session.commit()
                print(f"Erro ao enviar e-mail: {e}")


def verificar_pendentes_e_enviar_email_com_contexto():
    """Envolve a função em um contexto de aplicação."""
    with app.app_context():
        verificar_pendentes_e_enviar_email()


executors = {'default': ThreadPoolExecutor(1)}
scheduler = BackgroundScheduler(executors=executors)

def iniciar_agendador():
    """Configura o agendador para executar a verificação periodicamente."""
    if not scheduler.running:
        scheduler.add_job(
            func=verificar_pendentes_e_enviar_email_com_contexto,
            trigger='interval',
            hours=24,
            max_instances=1
        )
        scheduler.start()



# Rota Home para o RNC
@app.route('/home_rnc')
def home_rnc():
    return render_template('home_rnc.html')


# Rota para processar os dados do formulário de rnc
@app.route('/cadastro_rnc', methods=['GET', 'POST'])
@login_required
def cadastro_rnc():
    # Consulta os tipos de problema e os clientes ativos
    tipos_problema = TipoProblema.query.all()
    clientes = ClienteRNC.query.filter_by(ativo=True).all()
    usuarios = Usuario.query.filter_by(ativo=True).all()

    if request.method == 'POST':
        # Processar os dados do formulário
        projeto = request.form['projeto']
        cliente_id = request.form['cliente']  # Captura o ID do cliente selecionado no dropdown
        impacto_produto = request.form['impacto_produto']
        impacto_entrega = request.form['impacto_entrega']
        impacto_financeiro = float(request.form['impacto_financeiro'].replace(".", "").replace(",", "."))
        impacto_percepcao = request.form['impacto_percepcao']
        oc = request.form['oc']
        origem_setor = request.form['origem_setor']
        tipo_problema_id = request.form['tipo_problema_id']  # Captura o ID do tipo de problema selecionado
        descricao_nc = request.form['descricao_nc']
        centro_custo = request.form['centro_custo']
        solicitante = request.form.get('solicitante')
        email_solicitante = current_user.email
        plano_acao = request.form.get('plano_acao')

        # Obter o nome do cliente baseado no ID
        cliente = ClienteRNC.query.get(cliente_id)
        cliente_nome = cliente.nome if cliente else "Cliente não encontrado"

        ultimo_numero = database.session.query(database.func.max(CadastroRNC.n_solicitacao)).scalar()
        novo_numero = (ultimo_numero or 0) + 1

        # Criar o objeto de RNC e salvar no banco de dados
        cadastro = CadastroRNC(
            projeto=projeto,
            cliente=cliente_nome,
            impacto_produto=impacto_produto,
            impacto_entrega=impacto_entrega,
            impacto_financeiro=impacto_financeiro,
            impacto_percepcao=impacto_percepcao,
            oc=oc,
            origem_setor=origem_setor,
            tipo_problema_id=tipo_problema_id,
            descricao_nc=descricao_nc,
            centro_custo=centro_custo,
            n_solicitacao=novo_numero,
            solicitante=solicitante,
            email_solicitante=email_solicitante,
            plano_acao=plano_acao,
            usuario_id=current_user.id
        )
        database.session.add(cadastro)
        database.session.commit()

        # Configuração do envio de e-mail
        destinatarios = [dest.email for dest in Destinatario.query.filter_by(ativo=True).all()]
        subject = "Nova RNC Cadastrada"
        body = f"""
            Uma nova solicitação de cadastro de RNC foi realizada no sistema.

            Projeto: {projeto}
            Cliente: {cliente_nome}

            Por favor, acesse o sistema para revisar a solicitação.

            Atenciosamente.
        """
        msg = Message(subject=subject, recipients=destinatarios, body=body)

        # Envio assíncrono do e-mail
        send_async_email(msg)

        # Redireciona para a página de listagem de RNCs
        return redirect(url_for('listar_rnc'))

    # Renderiza o template com os tipos de problema e clientes
    return render_template('cadastro_rnc.html', tipos_problema=tipos_problema, clientes=clientes, usuarios=usuarios)


@app.route('/listar_rnc')
@login_required
def listar_rnc():
    # Recebe o parâmetro 'status' (pode ser None se não for especificado)
    status_filtro = request.args.get('status', None)

    query = CadastroRNC.query.join(Usuario).order_by(CadastroRNC.n_solicitacao.desc())

    # Se um status específico for passado, filtra os resultados
    if status_filtro and status_filtro in ["Pendente", "Aprovado", "Rejeitada"]:
        query = query.filter(CadastroRNC.status_rnc == status_filtro)

    cadastros = query.all()
    usuarios = Usuario.query.filter_by(ativo=True).all()

    return render_template('listar_rnc.html', cadastros=cadastros, usuarios=usuarios, status_filtro=status_filtro)





@app.route('/editar_rnc/<int:id>', methods=['POST'])
@login_required
def editar_rnc(id):
    if current_user.role != 'admin':  # Verifica se o usuário tem permissão
        return jsonify({'message': 'Você não tem permissão para isso!'}), 403

    # Busca o registro no banco de dados
    rnc = CadastroRNC.query.get_or_404(id)

    # Obtém os dados enviados no formulário
    solicitante = request.form.get('solicitante')
    plano_acao = request.form.get('plano_acao')

    # Atualiza os campos permitidos
    if solicitante:
        rnc.solicitante = solicitante
    if plano_acao:
        rnc.plano_acao = plano_acao

    try:
        # Salva as alterações no banco de dados
        database.session.commit()
        flash('Solicitação atualizada com sucesso!', 'alert-success')  # Mensagem para feedback
    except Exception as e:
        database.session.rollback()
        flash('Erro ao salvar alterações: ' + str(e), 'danger')
        return jsonify({'message': 'Erro ao salvar as alterações.'}), 500

    return redirect(url_for('listar_rnc'))  # Redireciona para a lista de RNCs



# Rota para visualizar os dados de uma solicitação de RNC
@app.route('/ver_rnc/<int:id>', methods=['GET'])
@login_required
def ver_rnc(id):
    rnc = CadastroRNC.query.get_or_404(id)
    return jsonify({
        'projeto': rnc.projeto,
        'cliente': rnc.cliente,
        'impacto_produto': rnc.impacto_produto,
        'impacto_entrega': rnc.impacto_entrega,
        'impacto_financeiro': rnc.impacto_financeiro,
        'impacto_percepcao': rnc.impacto_percepcao,
        'oc': rnc.oc,
        'origem_setor': rnc.origem_setor,
        'tipo_problema': rnc.tipo_problema,
        'descricao_nc': rnc.descricao_nc,
        'solicitante': rnc.solicitante,
        'plano_acao': rnc.plano_acao
    })



@app.route('/admin/tipo_problema', methods=['GET', 'POST'])
@login_required  # Certifique-se de que somente administradores podem acessar
def gerenciar_tipos_problema():
    if current_user.role != 'admin':
        flash('Acesso negado.', 'alert-danger')
        return redirect(url_for('home'))

    if request.method == 'POST':
        nome = request.form.get('nome')
        if nome:
            # Verifica se já existe um tipo de problema com o mesmo nome
            tipo_existente = TipoProblema.query.filter_by(nome=nome).first()
            if tipo_existente:
                flash('Este tipo de problema já existe.', 'alert-warning')
            else:
                novo_tipo = TipoProblema(nome=nome)
                database.session.add(novo_tipo)
                database.session.commit()
                flash('Tipo de problema adicionado com sucesso!', 'alert-success')
                return redirect(url_for('gerenciar_tipos_problema'))
        else:
            flash('O campo "Nome" não pode estar vazio.', 'alert-danger')

    # Recupera todos os tipos de problema para exibir na página
    tipos_problema = TipoProblema.query.all()
    return render_template('gerenciar_tipos_problema.html', tipos_problema=tipos_problema)



@app.route('/admin/tipo_problema/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_tipo_problema(id):
    if current_user.role != 'admin':
        flash('Acesso negado.', 'alert-danger')
        return redirect(url_for('home'))

    tipo_problema = TipoProblema.query.get_or_404(id)

    if request.method == 'POST':
        novo_nome = request.form.get('nome')
        if novo_nome:
            tipo_existente = TipoProblema.query.filter_by(nome=novo_nome).first()
            if tipo_existente and tipo_existente.id != id:
                flash('Já existe um tipo de problema com este nome.', 'alert-warning')
            else:
                tipo_problema.nome = novo_nome
                database.session.commit()
                flash('Tipo de problema atualizado com sucesso!', 'alert-success')
                return redirect(url_for('gerenciar_tipos_problema'))
        else:
            flash('O campo "Nome" não pode estar vazio.', 'alert-danger')

    return render_template('editar_tipo_problema.html', tipo_problema=tipo_problema)


@app.route('/aprovar_rnc/<int:id>', methods=['POST'])
@login_required
def aprovar_rnc(id):
    rnc = CadastroRNC.query.get_or_404(id)
    if rnc.status_rnc != 'Pendente':
        flash('Essa RNC já foi processada!', 'alert-warning')
        return redirect(url_for('listar_rnc'))

    rnc.status_rnc = 'Aprovado'
    database.session.commit()

    # Enviar email para o solicitante
    msg = Message(
        subject="Sua RNC foi aprovada!",
        recipients=[rnc.email_solicitante],  # Atualize para o email do solicitante
        body=f"Olá {rnc.email_solicitante},\n\nSua RNC de número {rnc.id} foi aprovada.\n\nAtenciosamente.",
    )
    send_async_email(msg)

    flash('RNC aprovada com sucesso e email enviado!', 'alert-success')
    return redirect(url_for('listar_rnc'))


@app.route('/rejeitar_rnc/<int:id>', methods=['POST'])
@login_required
def rejeitar_rnc(id):
    rnc = CadastroRNC.query.get_or_404(id)
    if rnc.status_rnc != 'Pendente':
        flash('Apenas RNCs pendentes podem ser rejeitadas.', 'alert-warning')
        return redirect(url_for('listar_rnc'))

    # Coleta o motivo da rejeição
    motivo_rejeicao = request.form.get('motivo_rejeicao')
    if not motivo_rejeicao:
        flash('O motivo da rejeição é obrigatório.', 'alert-danger')
        return redirect(url_for('listar_rnc'))

    # Atualiza o status da RNC
    rnc.status_rnc = 'Rejeitada'
    database.session.commit()

    # Envia o email de rejeição
    subject = f"RNC Rejeitada"
    body = f"Olá \n\nSua RNC foi rejeitada pelo seguinte motivo:\n\n{motivo_rejeicao}\n\nAtenciosamente."
    msg = Message(subject, recipients=[rnc.email_solicitante])
    msg.body = body
    send_async_email(msg)

    flash('RNC rejeitada e email enviado com sucesso.', 'success')
    return redirect(url_for('listar_rnc'))




@app.route('/admin/clientes', methods=['GET', 'POST'])
@login_required
def gerenciar_clientes():
    if request.method == 'POST':
        nome_cliente = request.form.get('nome_cliente')
        if nome_cliente:
            novo_cliente = ClienteRNC(nome=nome_cliente)
            try:
                database.session.add(novo_cliente)
                database.session.commit()
                flash('Cliente adicionado com sucesso!', 'alert-success')
            except:
                database.session.rollback()
                flash('Erro ao adicionar cliente. Verifique se já existe.', 'alert-danger')
        return redirect(url_for('gerenciar_clientes'))

    clientes = ClienteRNC.query.all()
    return render_template('admin_clientes.html', clientes=clientes)


@app.route('/admin/clientes/ativar_desativar/<int:cliente_id>')
def ativar_desativar_cliente(cliente_id):
    cliente = ClienteRNC.query.get_or_404(cliente_id)
    cliente.ativo = not cliente.ativo
    database.session.commit()
    flash(f'Cliente {"ativado" if cliente.ativo else "desativado"} com sucesso!', 'success')
    return redirect(url_for('gerenciar_clientes'))


@app.route('/admin/clientes/remover/<int:cliente_id>')
def remover_cliente(cliente_id):
    cliente = ClienteRNC.query.get_or_404(cliente_id)
    database.session.delete(cliente)
    database.session.commit()
    flash('Cliente removido com sucesso!', 'success')
    return redirect(url_for('gerenciar_clientes'))


@app.route('/relatorios')
@login_required
def relatorios():
    # Lista de clientes para o dropdown
    clientes = ClienteRNC.query.filter_by(ativo=True).all()

    # Lista de Tipos de Problema para o dropdown
    tipos_problema = TipoProblema.query.all()

    # Inicializa as variáveis
    cliente_id = request.args.get('cliente_id')  # Obtém o ID do cliente selecionado (ou None)
    tipo_problema_id = request.args.get('tipo_problema_id')
    data_inicio = request.args.get('data_inicio')
    data_fim = request.args.get('data_fim')

    cliente_selecionado = None
    tipo_problema_selecionado = None

    filtro = CadastroRNC.id.isnot(None)  # Filtro default que inclui todos os RNCs

    # Aplica filtro por cliente
    if cliente_id and cliente_id != "todos":
        cliente_selecionado = ClienteRNC.query.get(cliente_id)
        if cliente_selecionado:
            filtro = database.and_(filtro, CadastroRNC.cliente == cliente_selecionado.nome)

    # Aplica filtro por tipo de problema
    if tipo_problema_id and tipo_problema_id != "todos":
        tipo_problema_selecionado = TipoProblema.query.get(tipo_problema_id)
        if tipo_problema_selecionado:
            filtro = database.and_(filtro, CadastroRNC.tipo_problema_id == tipo_problema_selecionado.id)

    if data_inicio:
        filtro = database.and_(filtro, database.func.date(CadastroRNC.data_rnc) >= data_inicio)

    if data_fim:
        filtro = database.and_(filtro, database.func.date(CadastroRNC.data_rnc) <= data_fim)

    # Dados do gráfico de pizza
    tipo_problema_counts = (
        database.session.query(
            TipoProblema.nome,
            database.func.count(CadastroRNC.id)
        )
        .join(CadastroRNC, CadastroRNC.tipo_problema_id == TipoProblema.id)
        .filter(filtro)
        .group_by(TipoProblema.nome)
        .all()
    )

    # Dados do gráfico de barras
    cliente_counts = (
        database.session.query(
            CadastroRNC.cliente,
            database.func.count(CadastroRNC.id)
        )
        .filter(filtro)
        .group_by(CadastroRNC.cliente)
        .all()
    )

    # Soma do impacto financeiro
    impacto_financeiro_total = (
            database.session.query(database.func.sum(CadastroRNC.impacto_financeiro))
            .filter(filtro)
            .scalar() or 0
    )

    # Número total de RNCs
    numero_total_rncs = database.session.query(database.func.count(CadastroRNC.id)).filter(filtro).scalar() or 0

    # Impacto financeiro por cliente
    impacto_financeiro_por_cliente = (
        database.session.query(
            CadastroRNC.cliente,
            database.func.coalesce(database.func.sum(CadastroRNC.impacto_financeiro), 0)
        )
        .filter(filtro)
        .group_by(CadastroRNC.cliente)
        .all()
    )

    # Preparar dados para os gráficos
    labels_pizza = [row[0] for row in tipo_problema_counts]
    values_pizza = [row[1] for row in tipo_problema_counts]
    labels_barras = [row[0] for row in cliente_counts]
    values_barras = [row[1] for row in cliente_counts]
    labels_financeiro = [row[0] for row in impacto_financeiro_por_cliente]
    values_financeiro = [row[1] for row in impacto_financeiro_por_cliente]

    return render_template(
        'relatorios.html',
        clientes=clientes,
        tipos_problema=tipos_problema,
        cliente_selecionado=cliente_selecionado,
        labels_pizza=labels_pizza,
        values_pizza=values_pizza,
        labels_barras=labels_barras,
        values_barras=values_barras,
        labels_financeiro=labels_financeiro,
        values_financeiro=values_financeiro,
        impacto_financeiro_total=impacto_financeiro_total,
        numero_total_rncs=numero_total_rncs,
        data_inicio=data_inicio,
        data_fim=data_fim
    )


# Daqui pra baixo tratarei do Cadastro de Fornecedores
@app.route('/home_fornecedores')
def home_fornecedores():
    return render_template('home_fornecedores.html')


@app.route('/cadastro_fornecedores', methods=['GET', 'POST'])
@login_required
def cadastro_fornecedores():
    if request.method == 'POST':
        # Processar os dados do formulário
        nome = request.form['nome']
        cnpj = request.form['cnpj']
        situacao = request.form['situacao']
        atividade_principal = request.form['atividade_principal']
        atividades_secundarias = request.form['atividades_secundarias']
        logradouro = request.form['logradouro']
        numero = request.form['numero']
        complemento = request.form['complemento']
        municipio = request.form['municipio']
        bairro = request.form['bairro']
        uf = request.form['uf']
        cep = request.form['cep']
        email = request.form['email']
        telefone = request.form['telefone']
        inscricao_e = request.form['inscricao_e']
        regime_tributario = request.form['regime_tributario']
        cliente_tambem = request.form['cliente_tambem']
        nome_fantasia = request.form['nome_fantasia']
        email_contato = request.form['email_contato']
        email_contato2 = request.form['email_contato2']
        banco = request.form['banco']
        agencia = request.form['agencia']
        n_conta = request.form['n_conta']
        tipo_conta = request.form['tipo_conta']
        matriz_filial = request.form['matriz_filial']
        telefone_contato = request.form['telefone_contato']
        contato_pessoa = request.form['contato_pessoa']
        solicitante = request.form.get('solicitante')
        email_solicitante = current_user.email


        # Verifica se já existe um fornecedor com o mesmo CNPJ
        fornecedor_existente = CadastroFornecedores.query.filter(
            (CadastroFornecedores.cnpj == cnpj)
        ).first()

        if fornecedor_existente:
            flash('Já existe um fornecedor cadastrado com este CNPJ.', 'alert-danger')
            return redirect(url_for('cadastro_fornecedores'))


        ultimo_numero = database.session.query(database.func.max(CadastroFornecedores.n_solicitacao)).scalar()
        novo_numero = (ultimo_numero or 0) + 1

        # Criar o objeto de fornecedor e salvar no banco de dados
        novo_fornecedor = CadastroFornecedores(
            nome=nome,
            cnpj=cnpj,
            situacao=situacao,
            atividade_principal=atividade_principal,
            atividades_secundarias=atividades_secundarias,
            logradouro=logradouro,
            numero=numero,
            complemento=complemento,
            municipio=municipio,
            bairro=bairro,
            uf=uf,
            cep=cep,
            email=email,
            telefone=telefone,
            inscricao_e=inscricao_e,
            regime_tributario=regime_tributario,
            cliente_tambem=cliente_tambem,
            nome_fantasia=nome_fantasia,
            banco=banco,
            agencia=agencia,
            n_conta=n_conta,
            tipo_conta=tipo_conta,
            matriz_filial=matriz_filial,
            email_contato=email_contato,
            email_contato2=email_contato2,
            telefone_contato=telefone_contato,
            contato_pessoa=contato_pessoa,
            n_solicitacao=novo_numero,
            solicitante=solicitante,
            email_solicitante=email_solicitante,
            usuario_id=current_user.id
        )
        database.session.add(novo_fornecedor)
        database.session.commit()

        # Configuração do envio de e-mail
        destinatarios = [dest.email for dest in Destinatario.query.filter_by(ativo=True).all()]
        subject = "Novo Fornecedor Cadastrado!"
        body = f"""
                Uma nova solicitação de cadastro de Cliente/Fornecedor foi realizada no sistema.

                Nome: {nome}
                CNPJ: {cnpj}

                Por favor, acesse o sistema para revisar a solicitação.

                Atenciosamente.
                   """
        msg = Message(subject=subject, recipients=destinatarios, body=body)

        # Envio assíncrono do e-mail
        send_async_email(msg)

        flash('Fornecedor cadastrado com sucesso!', 'alert-success')

        # Redireciona para a página de listagem de fornecedores
        return redirect(url_for('listar_fornecedores'))

    # Renderiza o template para cadastro de fornecedores
    return render_template('cadastro_fornecedores.html')



@app.route('/listar_fornecedores', methods=['GET'])
@login_required
def listar_fornecedores():
    fornecedores = CadastroFornecedores.query.all()
    return render_template('listar_fornecedores.html', fornecedores=fornecedores)



@app.route('/consultar_cnpj/<cnpj>', methods=['GET'])
@login_required
async def consultar_cnpj(cnpj):
    url = f"https://www.receitaws.com.br/v1/cnpj/{cnpj}"

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    dados = await response.json()
                    if dados["status"] == "OK":
                        return jsonify(dados)
                    else:
                        return jsonify({"error": "CNPJ não encontrado ou inválido."}), 400
                else:
                    return jsonify({"error": f"Erro na requisição. Código HTTP: {response.status}"}), 500
        except asyncio.TimeoutError:
            return jsonify({"error": "Tempo limite excedido ao consultar API."}), 500
        except Exception as e:
            return jsonify({"error": f"Erro na conexão: {str(e)}"}), 500


@app.route('/consultar_ie/<cnpj>/<uf>', methods=['GET'])
@login_required
async def consultar_ie(cnpj, uf):
    url = f"https://open.cnpja.com/office/{cnpj}"

    async with aiohttp.ClientSession() as session:
        try:
            async with session.get(url, timeout=10) as response:
                if response.status == 200:
                    dados = await response.json()

                    for inscricao in dados.get("registrations", []):
                        if inscricao["state"] == uf:
                            return jsonify({
                                "inscricao_estadual": inscricao["number"],
                                "regime_tributario": inscricao["type"]["text"]  # Retorna o valor real do campo
                            })

                    return jsonify({"error": "Nenhuma inscrição estadual encontrada para esta UF."}), 404
                else:
                    return jsonify({"error": f"Erro na requisição. Código HTTP: {response.status}"}), 500

        except asyncio.TimeoutError:
            return jsonify({"error": "Tempo limite excedido ao consultar API."}), 500
        except Exception as e:
            return jsonify({"error": f"Erro na conexão: {str(e)}"}), 500


@app.route('/aprovar_cf/<int:id>', methods=['POST'])
@login_required
def aprovar_cf(id):
    fornecedor = CadastroFornecedores.query.get_or_404(id)
    if fornecedor.status_cf != 'Pendente':
        flash('Esse Cadastro já foi processado!', 'alert-warning')
        return redirect(url_for('listar_fornecedores'))

    # Coleta o código
    codigo_aprovacao = request.form.get('codigo_aprovacao')
    if not codigo_aprovacao:
        flash('O código é obrigatório para a aprovaçao.', 'alert-danger')
        return redirect(url_for('listar_fornecedores'))

    fornecedor.status_cf = 'Aprovado'
    database.session.commit()

    # Enviar email para o solicitante
    msg = Message(
        subject="Solicitação de Cadastro de Fornecedor aprovada!",
        recipients=[fornecedor.email_solicitante],  # Atualize para o email do solicitante
        body=f"Olá \n\nSua solicitação para o cadastro de Fornecedor foi aprovada com sucesso, com o código:\n\n{codigo_aprovacao}\n\nAtenciosamente."
    )
    send_async_email(msg)

    flash('Solicitação aprovada com sucesso e email enviado!', 'alert-success')
    return redirect(url_for('listar_fornecedores'))



@app.route('/rejeitar_cf/<int:id>', methods=['POST'])
@login_required
def rejeitar_cf(id):
    fornecedor = CadastroFornecedores.query.get_or_404(id)
    if fornecedor.status_cf != 'Pendente':
        flash('Apenas solicitações pendentes podem ser rejeitadas.', 'alert-warning')
        return redirect(url_for('listar_fornecedores'))

    # Coleta o motivo da rejeição
    motivo_rejeicao = request.form.get('motivo_rejeicao')
    if not motivo_rejeicao:
        flash('O motivo da rejeição é obrigatório.', 'alert-danger')
        return redirect(url_for('listar_fornecedores'))

    # Atualiza o status do cadastro de fornecedores/clientes
    fornecedor.status_cf = 'Rejeitada'
    database.session.commit()

    # Envia o email de rejeição
    subject = f"Solicitação de Cadastro de Fornecedor Rejeitada"
    body = f"Olá \n\nSua solicitação para o cadastro de Fornecedor foi rejeitada pelo seguinte motivo:\n\n{motivo_rejeicao}\n\nAtenciosamente."
    msg = Message(subject, recipients=[fornecedor.email_solicitante])
    msg.body = body
    send_async_email(msg)

    flash('Solicitação rejeitada e email enviado com sucesso.', 'alert-success')
    return redirect(url_for('listar_fornecedores'))



# Daqui para baixo se trata  se tratado cadastro de Clientes
#-----------------------------------------------------------------------------------------------------

@app.route('/cadastro_clientes', methods=['GET', 'POST'])
@login_required
def cadastro_clientes():
    if request.method == 'POST':
        # Processar os dados do formulário
        nome = request.form['nome']
        cnpj = request.form['cnpj']
        situacao = request.form['situacao']
        atividade_principal = request.form['atividade_principal']
        atividades_secundarias = request.form['atividades_secundarias']
        logradouro = request.form['logradouro']
        numero = request.form['numero']
        complemento = request.form['complemento']
        municipio = request.form['municipio']
        bairro = request.form['bairro']
        uf = request.form['uf']
        cep = request.form['cep']
        email = request.form['email']
        telefone = request.form['telefone']
        inscricao_e = request.form['inscricao_e']
        regime_tributario = request.form['regime_tributario']
        fornecedor_tambem = request.form['fornecedor_tambem']
        nome_fantasia = request.form['nome_fantasia']
        email_contato = request.form['email_contato']
        telefone_contato = request.form['telefone_contato']
        contato_pessoa = request.form['contato_pessoa']
        solicitante = request.form.get('solicitante')
        email_solicitante = current_user.email

        # Verifica se já existe um fornecedor com o mesmo CNPJ
        cliente_existente = CadastroClientes.query.filter(
            (CadastroClientes.cnpj == cnpj)
        ).first()

        if cliente_existente:
            flash('Já existe um Cliente cadastrado com este CNPJ.', 'alert-danger')
            return redirect(url_for('cadastro_clientes'))

        ultimo_numero = database.session.query(database.func.max(CadastroClientes.n_solicitacao)).scalar()
        novo_numero = (ultimo_numero or 0) + 1

        # Criar o objeto de fornecedor e salvar no banco de dados
        novo_cliente = CadastroClientes(
            nome=nome,
            cnpj=cnpj,
            situacao=situacao,
            atividade_principal=atividade_principal,
            atividades_secundarias=atividades_secundarias,
            logradouro=logradouro,
            numero=numero,
            complemento=complemento,
            municipio=municipio,
            bairro=bairro,
            uf=uf,
            cep=cep,
            email=email,
            telefone=telefone,
            inscricao_e=inscricao_e,
            regime_tributario=regime_tributario,
            fornecedor_tambem=fornecedor_tambem,
            nome_fantasia=nome_fantasia,
            email_contato=email_contato,
            telefone_contato=telefone_contato,
            contato_pessoa=contato_pessoa,
            n_solicitacao=novo_numero,
            solicitante=solicitante,
            email_solicitante=email_solicitante,
            usuario_id=current_user.id
        )
        database.session.add(novo_cliente)
        database.session.commit()

        # Configuração do envio de e-mail
        destinatarios = [dest.email for dest in Destinatario.query.filter_by(ativo=True).all()]
        subject = "Novo Cliente Cadastrado!"
        body = f"""
                Uma nova solicitação de cadastro de Cliente foi realizada no sistema.

                Nome: {nome}
                CNPJ: {cnpj}

                Por favor, acesse o sistema para revisar a solicitação.

                Atenciosamente.
                   """
        msg = Message(subject=subject, recipients=destinatarios, body=body)

        # Envio assíncrono do e-mail
        send_async_email(msg)

        flash('Cliente cadastrado com sucesso!', 'alert-success')

        # Redireciona para a página de listagem de fornecedores
        return redirect(url_for('listar_clientes'))

    # Renderiza o template para cadastro de fornecedores
    return render_template('cadastro_clientes.html')




@app.route('/listar_clientes', methods=['GET'])
@login_required
def listar_clientes():
    clientes = CadastroClientes.query.all()
    return render_template('listar_clientes.html', clientes=clientes)



@app.route('/aprovar_cliente/<int:id>', methods=['POST'])
@login_required
def aprovar_cliente(id):
    cliente = CadastroClientes.query.get_or_404(id)
    if cliente.status_cliente != 'Pendente':
        flash('Esse Cadastro já foi processado!', 'alert-warning')
        return redirect(url_for('listar_clientes'))

    # Coleta o código
    codigo_aprovacao = request.form.get('codigo_aprovacao')
    if not codigo_aprovacao:
        flash('O código é obrigatório para a aprovaçao.', 'alert-danger')
        return redirect(url_for('listar_fornecedores'))

    cliente.status_cliente = 'Aprovado'
    database.session.commit()

    # Enviar email para o solicitante
    msg = Message(
        subject="Sua Solicitação de Cadastro de Cliente foi aprovada!",
        recipients=[cliente.email_solicitante],  # Atualize para o email do solicitante
        body=f"Olá {cliente.email_solicitante},\n\nSua Solicitação de Cadastro de cliente foi aprovada!\n\nN° Solicitação:{cliente.id}\n\nAtenciosamente.",
    )
    send_async_email(msg)

    flash('Solicitação aprovada com sucesso e email enviado!', 'alert-success')
    return redirect(url_for('listar_clientes'))



@app.route('/rejeitar_cliente/<int:id>', methods=['POST'])
@login_required
def rejeitar_cliente(id):
    cliente = CadastroClientes.query.get_or_404(id)
    if cliente.status_cliente != 'Pendente':
        flash('Apenas solicitações pendentes podem ser rejeitadas.', 'alert-warning')
        return redirect(url_for('listar_clientes'))

    # Coleta o motivo da rejeição
    motivo_rejeicao = request.form.get('motivo_rejeicao')
    if not motivo_rejeicao:
        flash('O motivo da rejeição é obrigatório.', 'alert-danger')
        return redirect(url_for('listar_clientes'))

    # Atualiza o status do cadastro de fornecedores/clientes
    cliente.status_cliente = 'Rejeitada'
    database.session.commit()

    # Envia o email de rejeição
    subject = f"Solicitação de Cadastro de Cliente Rejeitada"
    body = f"Olá \n\nSua solicitação para o cadastro de Cliente foi rejeitada pelo seguinte motivo:\n\n{motivo_rejeicao}\n\nAtenciosamente."
    msg = Message(subject, recipients=[cliente.email_solicitante])
    msg.body = body
    send_async_email(msg)

    flash('Solicitação rejeitada e email enviado com sucesso.', 'alert-success')
    return redirect(url_for('listar_clientes'))