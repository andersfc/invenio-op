# -*- coding:utf-8 -*-
##
## This file is part of Invenio.
## Copyright (C) 2010, 2011, 2012 CERN.
##
## Invenio is free software; you can redistribute it and/or
## modify it under the terms of the GNU General Public License as
## published by the Free Software Foundation; either version 2 of the
## License, or (at your option) any later version.
##
## Invenio is distributed in the hope that it will be useful, but
## WITHOUT ANY WARRANTY; without even the implied warranty of
## MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
## General Public License for more details.
##
## You should have received a copy of the GNU General Public License
## along with Invenio; if not, write to the Free Software Foundation, Inc.,
## 59 Temple Place, Suite 330, Boston, MA 02111-1307, USA.
"""BibIndexEmptyTokenizer: useful for situations when we want to apply tokenizer
   for consistency, but we don't want to have any results from it.
"""


from invenio.legacy.bibindex.engine_config import CFG_BIBINDEX_INDEX_TABLE_TYPE
from invenio.modules.indexer.tokenizers.BibIndexTokenizer import BibIndexTokenizer



class BibIndexEmptyTokenizer(BibIndexTokenizer):
    """Empty tokenizer do nothing.
       It returns empty lists for tokenize_for_words, tokenize_for_pairs and tokenize_for_phrases methods.
    """

    def __init__(self, stemming_language = None, remove_stopwords = False, remove_html_markup = False, remove_latex_markup = False):
        """@param stemming_language: dummy
           @param remove_stopwords: dummy
           @param remove_html_markup: dummy
           @param remove_latex_markup: dummy
        """
        pass


    def get_tokenizing_function(self, wordtable_type):
        """Picks correct tokenize_for_xxx function depending on type of tokenization (wordtable_type)"""
        if wordtable_type == CFG_BIBINDEX_INDEX_TABLE_TYPE["Words"]:
            return self.tokenize_for_words
        elif wordtable_type == CFG_BIBINDEX_INDEX_TABLE_TYPE["Pairs"]:
            return self.tokenize_for_pairs
        elif wordtable_type == CFG_BIBINDEX_INDEX_TABLE_TYPE["Phrases"]:
            return self.tokenize_for_phrases


    def tokenize_for_words(self, phrase):
        return []

    def tokenize_for_pairs(self, phrase):
        return []

    def tokenize_for_phrases(self, phrase):
        return []

