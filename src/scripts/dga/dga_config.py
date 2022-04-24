import os.path as osp
HERE = osp.dirname(osp.abspath(__file__))
ngram_size = 4
dga_model_file = HERE+'/../../../models/dga_model.sav'
masked_ngram_values = ['n', 's', 'v', 'c']
