#!/usr/bin/env python3
# -*- coding: utf-8 -*-

__author__ = "norpadin"
__author_email__ = "npadin@gmail.com"
__copyright__ = "Copyright (c) 2024 norpadin"
__licensing__ = "GNU GENERAL PUBLIC LICENSE Version 3"
__annotations__ = ["Code created by norpadin, 2024"]


'''
----------------------------------------------------------------------------
Script name     : Device OOP for HVTv5
Created By      : Norberto P. Padín
Created Date    : 01/06/24
Version         : 0.2.7
Licensing       : GNU GENERAL PUBLIC LICENSE Version 3
---------------------------------------------------------------------------
Esta librería es necesaria para el correcto funcionamiento del script 
hvt4.py y hvt5.py.
---------------------------------------------------------------------------
'''

from ciscoconfparse2 import CiscoConfParse, IPv4Obj
import re


class Device(object):
    expected_kwargs = {
        'in_rexp': (str, 'default'),
        'in_weight': (str, 'default'),
        'in_test': (str, 'default'),
        'in_defa': (str, 'default'),
        'in_neg': (str, 'default'),
    }

    def __init__(self, type, pid, os, version, hostname, sernum):
        self.type = type
        self.pid = pid
        self.os = os
        self.version = version
        self.hostname = hostname
        self.sernum = sernum

    def ccp(self):
        shrunning = './repo/' + self.hostname + '_sh_run.cfg'
        return CiscoConfParse(shrunning, syntax='ios')

    @classmethod
    def validate_and_sanitize_kwargs(cls, received_kwargs):
        '''
        **kwargs sanitization for class

        Args:
                in_rexp: (optional) str.
                in_weight: (optional) str.
                in_test: (optional) str.
                in_defa: (optional) str.
                in_neg: (optional) str.

    Returns:
        Sanitized kwargs for class and subclasses.
        '''

        sanitized_kwargs = {}

        for key, (expected_type, default_value) in cls.expected_kwargs.items():
            if key in received_kwargs:
                value = received_kwargs[key]
                if not isinstance(value, expected_type):
                    raise TypeError(f"Expected {key} to be of type {
                                    expected_type.__name__}, but got {type(value).__name__}")
                # Example of additional sanitization: Ensure strings are non-empty
                if expected_type == str and not value:
                    raise ValueError(
                        f"Argument {key} should not be an empty string")
                # Example of additional sanitization: Ensure lists are non-empty
                if expected_type == list and not value:
                    raise ValueError(
                        f"Argument {key} should not be an empty list")
                sanitized_kwargs[key] = value
            else:
                sanitized_kwargs[key] = default_value

        # Check for unexpected keyword arguments
        for key in received_kwargs:
            if key not in cls.expected_kwargs:
                raise ValueError(f"Unexpected keyword argument: {key}")

        return sanitized_kwargs


class Switch(Device):
    pass


class Router(Device):
    pass


class Config(Device):

    def __init__(self, type, pid, os, version, hostname, sernum):
        super().__init__(type, pid, os, version, hostname, sernum)
        self.list = []
        self.check = False
        self.achieved = 0
        self.score = 0
        self.parse = super().ccp()

    def __iter__(self):
        for i in self.list:
            yield i

    def compver(self, ios_version: str):
        '''
        Compara las versiones del IOS en base a una de referencia, pero primero
        hay que separar la versión de la sub-versión. Para ello se separa con 
        expresiones regulares y grupos y se comparan las versiones por un lado
        y las sub-versiones por el otro.

        Args:
            self.
            ios_version (str): Version del IOS.

        Returns:
            bool: True si las versiones son iguales o superiores, False en caso
                  contrario.
            str: Tipo de IOS (IOS o IOS-XE).
            int: Score obtenido.
        '''

        self.achieved = 0
        base_integer = re.findall(r'(\d+).(?:.*)', ios_version)[0]

        r_ios = (r'(\d+).(\d+)\((\d+)\)(?:.*)')
        r_xe = (r'(\d+).(\d+).(\d+)(?:.*)')

        if int(base_integer) > 15:
            self.ios_type = 'IOS-XE'
            r1, r2, r3 = re.findall(r_xe, ios_version)[0]
            diff1 = int(r1) - 16
            diff2 = int(r2) - 6
            diff3 = int(r3) - 4
        else:
            self.ios_type = 'IOS'
            r1, r2, r3 = re.findall(r_ios, ios_version)[0]
            diff1 = int(r1) - 12
            diff2 = int(r2) - 4
            diff3 = int(r3) - 6

        if diff1 > 0:
            self.achieved = 5
            return True, self.ios_type, self.achieved
        elif diff1 < 0:
            return False, self.ios_type, self.achieved
        else:
            if diff2 > 0:
                self.achieved = 5
                return True, self.ios_type, self.achieved
            elif diff2 < 0:
                return False, self.ios_type, self.achieved
            else:
                if diff3 >= 0:
                    self.achieved = 5
                    return True, self.ios_type, self.achieved
                else:
                    return False, self.ios_type, self.achieved

    def users(self):
        '''
        Retorna los usuarios locales con sus niveles de privilegio.

        Args:
            self.

        Keyword Args:
            None.

        Returns:
            self.achieved : score obtenido (0 o 5).
            self.p01_check : True o False para usuarios con privilege 1.
            self.priv_01 : lista de usuarios privilegio 1.
            self.p15_check : True o False para usuarios con privilege 15.
            self.priv_15 : lista de usuarios privilegio 15.
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.p01_check = False
        self.p15_check = False
        self.new_parseo = []
        self.priv_01 = []
        self.priv_15 = []

        self.parseo = self.parse.find_objects(r'^username\s+(\S+)')
        self.new_parseo = [self.parseo[i].text for i in range(
            len(self.parseo))]

        pattern = re.compile(
            r'^username\s+(\S+)\s+(\w+)\s+(\d+)')
        for users in self.new_parseo:
            match = pattern.match(users)
            if match:
                username = match.group(1)
                privilege = match.group(2)
                privilege_level = int(match.group(3))
                self.usr_check = True
                if ((privilege == 'privilege') and (privilege_level == 15)):
                    self.priv_15.append((username))
                    self.p15_check = True
                else:
                    self.priv_01.append((username))
                    self.p01_check = True

        if self.p01_check and not self.p15_check:
            self.achieved = 5

        return self.achieved, self.p01_check, self.priv_01, self.p15_check, self.priv_15

    def aaa_newmod(self):
        '''
        Verifica si aaa new-model está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 5)
            self.check : True o False si está configurado
            self.list : lista vacía
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.parseo = self.parse.re_match_iter_typed(
            r'^aaa\s+new[-]model()', default=False)
        if not self.parseo:
            self.achieved = 5
            self.check = True

        return self.achieved, self.check, self.list

    def aaa_tacacs(self):
        '''
        Verifica si TACACS+ está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 5)
            self.check : True o False si está configurado
            self.list : IPv4 de los servidores
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        in_rexp = str(
            r"^tacacs[-]server\s+host\s+((?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)|(?:(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-_]*[a-zA-Z0-9])\.)+[a-zA-Z]{2,})$")
        self.parseo = self.parse.find_objects(in_rexp)
        prefix = 'tacacs-server host '
        if self.parseo:
            for i in range(len(self.parseo)):
                self.list.append(self.parseo[i].text.removeprefix(prefix))
                self.check = True
                self. achieved = 5

        return self.achieved, self.check, self.list

    def aaa_tacacs_sif(self):
        '''
        Verifica la interfaz de origen para identificarse en el servidor TACACS+.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 2)
            self.check : True o False si está configurado
            self.list : interfaz de orígen
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.parseo = self.parse.re_match_iter_typed(
            r'^ip\s+tacacs\s+source[-]interface\s+(\S+)$', default=False)
        if self.parseo:
            self.list.append(self.parseo)
            self.check = True
            self.achieved = 2

        return self.achieved, self.check, self.list

    def aaa_radius(self):
        '''
        Verifica si RADIUS está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 2)
            self.check : True o False si está configurado
            self.list : lista vacía
        '''

        self.list = []
        self.check = False
        self.parseo = self.parse.re_match_iter_typed(
            r'^radius\s+server\s+(\S+)$')
        if self.parseo:
            self.list.append(self.parseo)
            self.check = True
            self.achieved = 2

        return self.achieved, self.check, self.list

    def aaa_radius_sif(self):
        '''
        Verifica la interfaz de origen para identificarse en el servidor RADIUS.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 1)
            self.check : True o False si está configurado
            self.list : interfaz de orígen
        '''
        self.list = []
        self.check = False
        self.achieved = 0
        self.parseo = self.parse.re_match_iter_typed(
            r'^ip\s+radius\s+source[-]interface\s+(\S+)', default=False)
        if self.parseo != 'False':
            self.check = True
            self.achieved = 1

        obj = self.parse.find_child_objects(
            r'^aaa\s+group\s+server\s+radius\s+(\S+)',
            r'^\s+ip\s+radius\s+source[-]interface\s+(\S+)')
        if obj:
            for child_obj in obj:
                if_obj_match = re.search(
                    r'^\s+ip\s+radius\s+source[-]interface\s+(\S+)', child_obj.text)
                if if_obj_match:
                    self.list = if_obj_match.group(1)
                    self.check = True
                    self.achieved = 1

        return self.achieved, self.check, self.list

    def aaa_authe_login(self):
        '''
        Verifica si authentication login está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.list : métodos por órden de aparición
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.parseo = self.parse.re_match_iter_typed(
            r'^aaa\s+authentication\s+login\s+(.*)',
            default=0)
        if str(self.parseo) != '0':
            auth_methods_pattern = re.compile(r'(.*)')
            match = auth_methods_pattern.search(self.parseo)
            self.check = True
            self.achieved = 3
            self.list = re.findall(
                r'(?:default|local|group\s+(?:tacacs\+|radius))', match.group(1))

        return self.achieved, self.check, self.list

    def aaa_authe_vty(self):
        '''
        Verifica si la VTYs tienen especificadas la autenticación.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 2)
            self.check : True o False si está configurado
            self.list : métodos por órden de aparición en las VTYs
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        vty = [r'0\s4', r'5\s15', r'16\s31']
        for line_vty in vty:
            obj = self.parse.find_child_objects(
                r'^line\s+vty\s+' + line_vty,
                r'^\s+login\s+authentication\s+(\S+)')
            if not obj:
                self.list.append('default')
            else:
                self.list = []
                for child_obj in obj:
                    if_obj_match = re.search(
                        r'^\s+login\s+authentication\s+(\S+)', child_obj.text)
                    if if_obj_match:
                        self.check = True
                        self.list.append(if_obj_match.group(1))
                        self.achieved = 2

        return self.achieved, self.check, self.list

    def aaa_authe_ena(self):
        '''
        Verifica si aaa authentication enable está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.list : métodos por órden de aparición
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.parseo = self.parse.re_match_iter_typed(
            r'^aaa\s+authentication\s+enable\s+(.*)',
            default=0)
        if str(self.parseo) != '0':
            auth_pattern = re.compile(r'(.*)')
            match = auth_pattern.search(self.parseo)
            self.check = True
            self.achieved = 3
            self.list = re.findall(
                r'(?:default|local|group\s+(?:tacacs\+|radius))', match.group(1))

        return self.achieved, self.check, self.list

    def aaa_autho_exec(self):
        '''
        Verifica si aaa authentication exec está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.list : métodos por órden de aparición
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.parseo = self.parse.re_match_iter_typed(
            r'^aaa\s+authorization\s+exec\s+(.*)',
            default=0)
        if str(self.parseo) != '0':
            auth_pattern = re.compile(r'(.*)')
            match = auth_pattern.search(self.parseo)
            self.list = re.findall(
                r'(?:default|local|group\s+(?:tacacs\+|radius))', match.group(1))
            self.achieved = 3
            self.check = True

        return self.achieved, self.check, self.list

    def aaa_autho_comm(self):
        '''
        Verifica si aaa authorization commands está configurado.

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.p01_check : True o False para usuarios con privilege 1
            self.priv_01 : lista de usuarios privilegio 1
            self.p15_check : True o False para usuarios con privilege 15
            self.priv_15 : lista de usuarios privilegio 15
        '''

        self.list = []
        self.check = False
        self.achieved = 0
        self.p01_check = False
        self.p15_check = False
        self.new_parseo = []
        self.priv_01 = []
        self.priv_15 = []

        in_rexp = str(r'^aaa\s+authorization\s+commands\s+(.*)')
        self.parseo = self.parse.find_objects(in_rexp)
        prefix = 'aaa authorization commands '
        if self.parseo:
            for i in range(len(self.parseo)):
                self.new_parseo.append(
                    self.parseo[i].text.removeprefix(prefix))
                self.check = True
                self. achieved = 3

        pattern = re.compile(r'^(\d+)\s+(.*)')
        for comm in self.new_parseo:
            match = pattern.match(comm)
            if match:
                privilege = match.group(1)
                comm_order = match.group(2)
                self.check = True
                self.achieved = 5
                if int(privilege) == 15:
                    self.priv_15 = re.findall(
                        r'(?:default|none|group\s+tacacs\+)', comm_order)
                    self.p15_check = True
                else:
                    self.priv_01 = re.findall(
                        r'(?:default|local|group\s+tacacs\+)', comm_order)
                    self.p01_check = True

        return self.achieved, self.check, self.p01_check, self.priv_01, self.p15_check, self.priv_15

    def aaa_max_fail(self):
        '''
        Verifica si la máxima cantidad de intentos de login está por defecto (5) o si tuene un valor menor sugerido (3).

        Args:
            self

        Keyword Args:
            None

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.list : cantidad de reintentos. Vacía si es por defecto.
        '''

        self.list = []
        self.check = False
        self.achieved = 0

        self.parseo = self.parse.re_match_iter_typed(
            r'^aaa\s+local\s+authentication\s+attempts\s+max-fail\s+(\d+)',
            default=0)

        parsed_value = int(self.parseo)
        if (parsed_value != 0) and (parsed_value <= 3):
            self.list.append(int(self.parseo))
            self.achieved = 2
            self.check = True

        return self.achieved, self.check, self.list

    def snmp(self, **kwargs):
        '''
        Verifica si SNMP está configurado.

        Args:
            self

        Keyword Args:
            in_rexp (str): expresión regular
            in_weight (str): score

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.list : métodos por órden de aparición
        '''

        pubpriv = []
        new_parseo_clean = []
        new_parseo_acl = []
        check3 = False
        score = 0

        sanitized_kwargs = self.validate_and_sanitize_kwargs(kwargs)

        for key, value in sanitized_kwargs.items():
            setattr(self, key, value)

        pattern = re.compile(fr'{self.in_rexp}')

        self.parseo = self.parse.find_objects(pattern)

        new_parseo_clean = [self.parseo[i].text[22:]
                            for i in range(len(self.parseo))
                            if not re.search(
            pattern, self.parseo[i].text).group(3)]

        new_parseo_acl = [
            self.parseo[i].text[22:]
            for i in range(len(self.parseo))
            if re.search(pattern, self.parseo[i].text).group(3)]

        pubpriv = [
            self.parseo[i].text[22:] for i in range(len(self.parseo))
            if (re.search(pattern, self.parseo[i].text).group(2)).lower()
            in ["public", "private"]]

        if pubpriv:
            check3 = True
        else:
            score += 3

        if not new_parseo_clean and not new_parseo_acl:
            score = 6
            return True, False, new_parseo_clean, new_parseo_acl, check3, score
        elif not new_parseo_clean and new_parseo_acl:
            score += 3
            return True, True, new_parseo_clean, new_parseo_acl, check3, score
        elif new_parseo_clean and new_parseo_acl:
            return False, True, new_parseo_clean, new_parseo_acl, check3, score
        else:
            return False, False, new_parseo_clean, new_parseo_acl, check3, score

    def snmp_hte(self, **kwargs):
        '''
        Verifica si aspectos(ACLs, comunidades, traps) del SNMP están configurados.

        Args:
            self.

        Keyword Args:
            in_rexp (str): expresión regular.
            in_weight (str): score.

        Returns:
            self.achieved : score obtenido (0 o 3)
            self.check : True o False si está configurado
            self.list : métodos por órden de aparición
        '''

        new_parseo_clean = []
        new_parseo_clean_1 = []
        new_parseo_clean_2 = []
        check1 = False
        check2 = False
        check3 = False
        score = 0

        sanitized_kwargs = self.validate_and_sanitize_kwargs(kwargs)
        for key, value in sanitized_kwargs.items():
            setattr(self, key, value)

        sub_test = self.in_neg
        pattern = re.compile(r'\bversion\s+(2c|3)\b')
        self.parseo = self.parse.find_objects(self.in_rexp)

        if self.parseo:
            new_parseo_clean = self.parseo[0].text
            if sub_test == "trap-source":
                score = self.in_weight
                check1 = True
                return check1, check2, sub_test, new_parseo_clean, new_parseo_clean_2, score
            elif sub_test == "enable":
                score = self.in_weight
                check1 = True
                return check1, check2, sub_test, new_parseo_clean, new_parseo_clean_2, score
            else:
                for i in range(len(self.parseo)):
                    match = re.search(pattern, self.parseo[i].text)
                    if match:
                        alpha = self.parseo[i].text[12:].strip()
                        new_parseo_clean_1.append(alpha)
                        check1 = True
                        check2 = True
                    else:
                        alpha = self.parseo[i].text[12:].strip()
                        new_parseo_clean_2.append(alpha)
                        check1 = True
                        check3 = True
                if check3 and check2:
                    score = 0
                    check2 = False
                else:
                    score = self.in_weight
                return check1, check2, sub_test, new_parseo_clean_1, new_parseo_clean_2, score
        else:
            score = 0
            check1 = check2 = False
            return check1, check2, sub_test, new_parseo_clean_1, new_parseo_clean_2, score

    # def func_objects(in_parse: CiscoConfParse, in_test: str, in_rexp: str,
    #                 in_neg: str, in_weight: int) -> tuple[bool, list[str], int]:

    def objects(self, **kwargs):
        '''
        Busca objetos y retorna True o False si la lista se encuentra vacía
        (exact match) o con caracteres (no match).

        Args:
            self.

        Keyword Args:
            in_test (str): Nombre de la prueba.
            in_rexp (str): expresión regular.
            in_defa (str): Valor por defecto.
            in_neg (str): Valor negativo.
            in_weight (str): score.

        Returns:
            self.check : True o False si está configurado.
            self.list : Cuando sea necesario retornar valores.
            self.achieved : score obtenido.
        '''

        sanitized_kwargs = self.validate_and_sanitize_kwargs(kwargs)
        for key, value in sanitized_kwargs.items():
            setattr(self, key, value)

        score = int(self.in_weight)
        self.parseo = self.parse.find_objects(self.in_rexp)

        if not self.parseo and eval(self.in_neg):
            score = int(0)
            return False, None, score
        elif not self.parseo and not eval(self.in_neg):
            return False, None, score
        elif self.parseo and eval(self.in_neg):
            return True, None, score
        else:
            score = int(0)
            return False, None, score

    def typed(self, **kwargs):
        '''
        Busca objetos y retorna True o False si hay un exact match
        o con caracteres (no match)

        Args:
            in_parse (CiscoConfParse): Objeto CiscoConfParse.
            in_test (str): Nombre de la prueba.
            in_rexp (str): Expresión regular.
            in_defa (str): Valor por defecto.
            in_neg (str): Valor negativo.
            in_weight (int): Entero.

        Returns:
            bool: True si compliance, False en caso contrario.
            int: Score obtenido.
        '''

        sanitized_kwargs = self.validate_and_sanitize_kwargs(kwargs)
        for key, value in sanitized_kwargs.items():
            setattr(self, key, value)

        self.achieved = int(0)
        self.parseo = self.parse.re_match_iter_typed(
            self.in_rexp, default=self.in_defa)

        if (len(self.parseo) == 0 or len(self.parseo) > 5) and (not eval(self.in_neg)):
            self.achieved = int(self.in_weight)
            return True, self.achieved
        elif (len(self.parseo) == 0 or len(self.parseo) > 5) and eval(self.in_neg):
            return False, self.achieved
        elif eval(self.parseo) and eval(self.in_neg):
            self.achieved = int(self.in_weight)
            return True, self.achieved
        else:
            return False, self.achieved
