import Settings from '../models/Settings.js';

/**
 * Get settings for the current user or global settings
 */
export const getSettings = async (req, res, next) => {
  try {
    const userId = req.user.id;
    
    // Try to find user-specific settings
    let settings = await Settings.findOne({ userId });
    
    // If no settings exist for this user, return default or global settings
    if (!settings) {
      // In a real multi-tenant app, you might want to return global defaults
      // For now, let's create a default record for the user if it doesn't exist
      settings = new Settings({ userId });
      await settings.save();
    }
    
    res.status(200).json({
      success: true,
      data: settings
    });
  } catch (error) {
    next(error);
  }
};

/**
 * Update settings for the current user
 */
export const updateSettings = async (req, res, next) => {
  try {
    const userId = req.user.id;
    const updateData = req.body;
    
    let settings = await Settings.findOneAndUpdate(
      { userId },
      { $set: updateData },
      { new: true, upsert: true, runValidators: true }
    );
    
    res.status(200).json({
      success: true,
      message: 'Settings updated successfully',
      data: settings
    });
  } catch (error) {
    next(error);
  }
};
