#!/bin/bash

echo "Fala teu email do GitHub aí, pae: "
read email

echo "Cola o token aí, doido: "
read -s token  # -s oculta a digitação do token por segurança

echo "Quem és tu? (Usuário do GitHub): "                                                        
read user

echo "Fala o nome do repositório: "
read repo

git remote set-url origin https://$email:$token@github.com/$user/$repo.git

echo "URL do repositório atualizada com sucesso!"

