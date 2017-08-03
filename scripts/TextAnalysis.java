package org.owasp.passfault;

import org.owasp.passfault.api.*;
import org.owasp.passfault.finders.*;
import org.owasp.passfault.impl.*;
import org.owasp.passfault.dictionary.*;
import org.owasp.passfault.keyboard.*;

import java.io.IOException;


public class TextAnalysis
{
	public static void main(String [] args)
	{

		String password = "1qaz6yhn 11.05.1997";
		PatternFinder finder = null;

		// Dictionary finder
		/*
		String current = "";
		FileDictionary dictionary = null;

		try{
			current = new java.io.File(".").getCanonicalPath();
		} catch (IOException e)
		{
			System.out.println("ERROR: " + e);
		}

		String filename = "tiny-lower.words";
		String path = "/core/src/main/java/org/owasp/passfault/";

		path = "/core/src/test/resources/dictionaries/";

		try
		{
			dictionary = FileDictionary.newInstance(
				current + path + filename,
				"testovaci_subor"
				);
		} catch (IOException e)
		{
			System.out.println("ERROR: " + e);
		}

		finder = new DictionaryPatternsFinder(
			dictionary,
			new l337SubstitutionStrategy(),
			new FilteringPatternCollectionFactory()
			);
		*/

		// Date finder
		finder = new DateFinder(
			new FilteringPatternCollectionFactory()
		);

		// Random_class finder
		/*
		finder = new RandomClassesFinder(
			2,
			new FilteringPatternCollectionFactory()
			);
		*/

		// Key_sequence finder
		/*
		finder = new KeySequenceFinder(
			new EnglishKeyBoard(),
			new FilteringPatternCollectionFactory()
		);
		*/

		PatternCollection patterns = finder.search(password);
		AnalysisResult analysisResult = new PatternsAnalyzerImpl().analyze(
			patterns
		);
		System.out.println(analysisResult.toString());
	}
}
