package org.owasp.passfault;

import org.owasp.passfault.api.*;
import org.owasp.passfault.finders.*;
import org.owasp.passfault.impl.*;
import org.owasp.passfault.dictionary.*;
import org.owasp.passfault.keyboard.*;

import java.io.IOException;
import java.util.ArrayList;


public class TextAnalysis
{
	public static void main(String [] args)
	{
		String password = args[0];

		PatternFinder finder = null;
		ArrayList<PatternFinder> findersCollection = new ArrayList<PatternFinder>();

		// Dictionary finder
		String current = "";
		FileDictionary dictionary = null;

		String mainPath = "/core/src/main/java/org/owasp/passfault";
		String subPath = "/resources/dictionaries";
		String filename = "/english.words";

		try
		{
			current = new java.io.File(".").getCanonicalPath();

			dictionary = FileDictionary.newInstance(
				current + mainPath + subPath + filename,
				"testovaci_subor"
				);
		} catch (IOException e)
		{
			System.out.println("ERROR: " + e);
		}
		

		
		// Date finder
		findersCollection.add(new DateFinder(
			new FilteringPatternCollectionFactory()
		));

		// Key_sequence finder
		findersCollection.add(
			new KeySequenceFinder(
				new EnglishKeyBoard(),
				new FilteringPatternCollectionFactory()
			)
		);

		// Reverse pattern finder
		findersCollection.add(new ReversePatternDecoratorFinder(
			new DictionaryPatternsFinder(
				dictionary,
				new ExactWordStrategy(),
				new FilteringPatternCollectionFactory()
			),
			new FilteringPatternCollectionFactory()
		));


		// Search for patterns
		CompositeFinder complexFinder = new SequentialFinder(
			findersCollection,
			new FilteringPatternCollectionFactory()
		);
		

		/*
		// Not working
		// TODO
		// Configurate propsBuilder
		FinderByPropsBuilder propsBuilder = new FinderByPropsBuilder().setClassPathLoader(
			"org/owasp/passfault/wordlists/resources"
		); //loadDefaultWordLists();

		CompositeFinder complexFinder = null;

		try
		{
			complexFinder = new SequentialFinder(
				propsBuilder.build(),
				new FilteringPatternCollectionFactory()
			);
		} catch (IOException e)
		{
			System.out.println("ERROR: " + e);
		}
		*/

		PatternCollection patterns = complexFinder.search(password);
		AnalysisResult analysisResult = new PatternsAnalyzerImpl().analyze(
			patterns
		);
		System.out.println(analysisResult.toString());
	}
}
