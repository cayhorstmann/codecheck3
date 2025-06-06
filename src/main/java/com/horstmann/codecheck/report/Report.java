package com.horstmann.codecheck.report;

import com.horstmann.codecheck.checker.Error;
import com.horstmann.codecheck.checker.Score;

import java.awt.image.BufferedImage;
import java.nio.file.Path;
import java.util.List;
import java.util.Set;

public interface Report
{
    public class Match
    {
        public String actual;
        public String expected;
        public boolean matches;
        public String explanation;
    }

   Report header(String section, String text);
   
   Report run(String caption, String mainclass, boolean hidden);

   Report output(CharSequence text);

   Report error(String message);

   Report systemError(String message);

   Report systemError(Throwable t);
   
   default Report condition(boolean passed, boolean forbidden, Path path, String regex, String message) {	   
	   if (!passed) {
		   if (message == null) message = (forbidden ? "Found " : "Did not find ") + regex;
		   error(path + ": " + message);
	   }
	   return this;
   }

   Report image(String caption, String filename, BufferedImage image);
   
   Report file(String file, String contents);
   Report file(String file, byte[] contents, boolean hidden);
   
   Report args(String args);
   
   Report input(String input);

   Report add(Score score);
   
   Report pass(boolean b);
   
   Report compareTokens(String filename, List<Match> matches);
   Report output(List<String> lines, Set<Integer> matches, Set<Integer> mismatches);
   
   // TODO: record for RunTableRow
   Report runTable(String[] functionNames, String[] argNames, String[][] args, String[] actual, String[] expected, boolean[] outcomes, boolean[] hidden, String mainclass);
   
   Report comment(String key, String value);
   default Report attribute(String key, Object value) { return this; } 

   Report footnote(String text);
   
   default void close() {}
   String getText();
   
   default Report errors(List<Error> errors) { return this; }
   
   String extension();
}