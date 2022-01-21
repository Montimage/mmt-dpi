pdflatex $1.tex;
bibtex $1.aux;
pdflatex $1.tex;
echo "Done!";