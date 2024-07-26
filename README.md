# Hackathon FIAP
## Lambda de autenticação de Pacientes

Esse componente serve para autenticar os usuários do perfil de paciente e retornar um token JWT para realizar a autorização em nosso Api Gateway.

A requisição é feita via API Gateway e retorna um token JWT.

## Auth
**Endpoint:** *https://*****pikwe9lct4.execute-api.us-east-1.amazonaws.com/prod/token/paciente*<br />
**Método:** *GET*

**Request Example:** 
<br />
```json
{
    "cpf": "22496741839",
    "email": "22496741839@teste.com",
    "password": "Teste@22496741839"
}
```
**Response Example:** 
```json
{
    "statusCode": 200,
    "body": "{\"token\": \"eyJraWQiOiJjR1hjR2NvVnhodTVJMW5pYU9YM2t5RnlneVBWbjJ6Ym10M3RFMHFpTTJjPSIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiI1YWMxYjY5ZS1jM2VlLTRkNjctOTA4Mi05MTg5NDcyYzVmZWEiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwiaXNzIjoiaHR0cHM6XC9cL2NvZ25pdG8taWRwLnVzLWVhc3QtMi5hbWF6b25hd3MuY29tXC91cy1lYXN0LTJfb05VZUM5M1hkIiwiY29nbml0bzp1c2VybmFtZSI6IjEyMzQ1Njc4OTEwIiwib3JpZ2luX2p0aSI6IjhmNjYxOGQxLTNhM2MtNGU1ZS04OWU4LWZiYjY5YjI2NGI3YSIsImF1ZCI6InY3MTRxamZzdHVlbG1pNmJuYmdwOWpsYzIiLCJldmVudF9pZCI6Ijk4ZjliZTNiLTVmMDgtNGE4Mi04YTAyLTUxZWZlNmIzNThkOCIsInRva2VuX3VzZSI6ImlkIiwiYXV0aF90aW1lIjoxNzEwODkyMTI5LCJleHAiOjE3MTA4OTU3MjksImlhdCI6MTcxMDg5MjEyOSwianRpIjoiOWEwMWVkMzItZTYxMy00ZGQ0LTgzZmYtMjZiZDVjOWI5YWRmIiwiZW1haWwiOiJndWlsaGVybWVwY3N0b3JlQGdtYWlsLmNvbSJ9.E3kRkpGQdOTzPOq8hMFllm3N7LW24KvQiwTfMmMtcKN6ZKJPXooJysbT5NuQu8ut3fOLVjc33E6B7oDqIsUO1tbCtI9OQvtGe54QX_NfSaY0Fpp3YpkGFXTwi-0BiW9A8OwwIlHxBWUnKCLsbp5aE21sgVx2erY7FaZwb9fvgbYmdHpqTr8650BgNUsOa5BbfHTxaUpl4bgsywY0JNMNBk3LYguvfHu9egEwWWgZ_DJKEOZbcM-HA2cJ3hnPqQIbU-UPDM38crt98Nci95JftHSBTsZWYVm2-dEy2MKE6uZZ5mtOo83Rt02_vBTUlk3rKn8j5i6TGZEncF8QIeuqOA\"}"
}
```
![image](https://github.com/Tech-Challenge-FIAP-GLR/lambda_techchallenge/assets/77997696/de42db08-619a-4648-a87c-0a1b4c746c64)
