# Udacity Item Catalog - Viz Gallery

A simple web application that provides a list of items within a variety of categories and integrate third party user registration and authentication. Authenticated users have the ability to post, edit, and delete their own items.
As data vizualiazation enthusiast I want to enable users to share the greatest work they can find on [Tableau Public](https://public.tableau.com/en-us/s/gallery).

## Set Up

1. Make sure you have [Vagrant](https://www.vagrantup.com/) and [VirtualBox](https://www.virtualbox.org/) installed on your machine.
2. Clone this respository to your local machine:
`git clone https://github.com/Niemzok/vizcatalog-project.git`

## Usage

Launch the Vagrant VM from inside the *project* folder with:

`vagrant up`

Then access the shell with:

`vagrant ssh`

Move into the project folder in the virtual machine using
`cd /vagrant`

Initially setup the database by running:
`python db_setup.py`

Then run the application:

`python app.py`

After the last command you are able to browse the application at this URL:

`http://localhost:5000/`
