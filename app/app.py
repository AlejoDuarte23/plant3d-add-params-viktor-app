import viktor as vkt


class Parametrization(vkt.Parametrization):
    pass # Welcome to VIKTOR! You can add your input fields here. Happy Coding!


class Controller(vkt.Controller):
    parametrization = Parametrization
